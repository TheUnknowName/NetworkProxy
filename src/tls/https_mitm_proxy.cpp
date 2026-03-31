#include "tls/https_mitm_proxy.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "patch/patch_engine.h"
#include "protocol/protocol_detector.h"
#include "protocol/protocol_manager.h"
#include "tls/certificate_manager.h"
#include "tls/openssl_process.h"

#include <WS2tcpip.h>

namespace network_proxy {

namespace {

void close_socket_if_valid(SOCKET socket_handle) {
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
}

std::string quote_argument(const std::string& value) {
    return "\"" + value + "\"";
}

void relay_socket_stream(SOCKET source_socket, SOCKET target_socket, std::atomic_bool& stop_requested) {
    char buffer[8192];
    while (!stop_requested.load()) {
        const int received = recv(source_socket, buffer, sizeof(buffer), 0);
        if (received <= 0) {
            break;
        }

        int sent_offset = 0;
        while (sent_offset < received) {
            const int sent = send(target_socket, buffer + sent_offset, received - sent_offset, 0);
            if (sent <= 0) {
                stop_requested.store(true);
                return;
            }
            sent_offset += sent;
        }
    }

    stop_requested.store(true);
}

}  // namespace

HttpsMitmProxy::HttpsMitmProxy(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger) {
}

bool HttpsMitmProxy::initialize() {
    if (!config_.https_mitm_enabled) {
        logger_.info("https mitm disabled by config");
        return true;
    }

    if (config_.https_ca_cert_path.empty() || config_.https_ca_key_path.empty()) {
        logger_.error("https mitm enabled but CA certificate path or key path is empty");
        return false;
    }

    CertificateManager certificate_manager(logger_);
    std::string cert_error;
    if (!certificate_manager.validate_ca_files(config_.https_ca_cert_path, config_.https_ca_key_path, cert_error)) {
        logger_.error("https mitm ca validation failed: " + cert_error);
        return false;
    }

    std::error_code cache_error;
    std::filesystem::create_directories(config_.https_cert_cache_dir, cache_error);
    if (cache_error) {
        logger_.error("https mitm cache directory create failed: " + config_.https_cert_cache_dir);
        return false;
    }

    logger_.info("https mitm initialized with cache dir: " + config_.https_cert_cache_dir);
    return true;
}

bool HttpsMitmProxy::try_extract_sni_from_client_hello(std::string_view client_hello, std::string& server_name) const {
    server_name.clear();

    if (client_hello.size() < 5) {
        return false;
    }

    const auto read_u16 = [](const unsigned char* value) {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8U) | static_cast<std::uint16_t>(value[1]));
    };

    const unsigned char* data = reinterpret_cast<const unsigned char*>(client_hello.data());
    const std::size_t size = client_hello.size();

    if (data[0] != 0x16 || data[1] != 0x03) {
        return false;
    }

    if (size < 9 || data[5] != 0x01) {
        return false;
    }

    std::size_t offset = 5;
    if (offset + 4 > size) {
        return false;
    }

    const std::size_t handshake_length = (static_cast<std::size_t>(data[offset + 1]) << 16U) |
        (static_cast<std::size_t>(data[offset + 2]) << 8U) |
        static_cast<std::size_t>(data[offset + 3]);
    offset += 4;
    if (offset + handshake_length > size) {
        return false;
    }

    if (offset + 34 > size) {
        return false;
    }
    offset += 34;

    if (offset + 1 > size) {
        return false;
    }
    const std::size_t session_id_length = data[offset];
    offset += 1 + session_id_length;

    if (offset + 2 > size) {
        return false;
    }
    const std::size_t cipher_suites_length = read_u16(data + offset);
    offset += 2 + cipher_suites_length;

    if (offset + 1 > size) {
        return false;
    }
    const std::size_t compression_methods_length = data[offset];
    offset += 1 + compression_methods_length;

    if (offset + 2 > size) {
        return false;
    }
    const std::size_t extensions_length = read_u16(data + offset);
    offset += 2;

    const std::size_t extensions_end = (offset + extensions_length < size) ? (offset + extensions_length) : size;
    while (offset + 4 <= extensions_end) {
        const std::uint16_t extension_type = read_u16(data + offset);
        const std::size_t extension_length = read_u16(data + offset + 2);
        offset += 4;
        if (offset + extension_length > extensions_end) {
            break;
        }

        if (extension_type == 0x0000) {
            std::size_t sni_offset = offset;
            if (sni_offset + 2 > extensions_end) {
                return false;
            }
            const std::size_t sni_list_length = read_u16(data + sni_offset);
            sni_offset += 2;
            const std::size_t extension_end = offset + extension_length;
            const std::size_t sni_end = (sni_offset + sni_list_length < extension_end) ? (sni_offset + sni_list_length) : extension_end;

            while (sni_offset + 3 <= sni_end) {
                const unsigned char name_type = data[sni_offset];
                const std::size_t name_length = read_u16(data + sni_offset + 1);
                sni_offset += 3;
                if (sni_offset + name_length > sni_end) {
                    return false;
                }

                if (name_type == 0x00) {
                    server_name.assign(reinterpret_cast<const char*>(data + sni_offset), name_length);
                    return !server_name.empty();
                }

                sni_offset += name_length;
            }
        }

        offset += extension_length;
    }

    return false;
}

bool HttpsMitmProxy::ensure_leaf_certificate_for_host(const std::string& host_name, std::filesystem::path& cert_path, std::filesystem::path& key_path) const {
    CertificateManager certificate_manager(logger_);
    std::string cert_error;
    if (!certificate_manager.generate_leaf_certificate(
            host_name,
            config_.https_ca_cert_path,
            config_.https_ca_key_path,
            config_.https_cert_cache_dir,
            config_.openssl_bin_path,
            cert_path,
            key_path,
            cert_error)) {
        logger_.error("generate leaf certificate failed: " + cert_error);
        return false;
    }

    return true;
}

bool HttpsMitmProxy::patch_https_plaintext_http(std::string& plaintext_payload, const std::string& direction, ProtocolManager& protocol_manager, PatchEngine& patch_engine) const {
    ProtocolContext context;
    context.direction = direction;
    context.protocol_kind = detect_protocol_kind(plaintext_payload);

    bool handled = protocol_manager.patch_payload(plaintext_payload, context);
    if (!handled && context.protocol_kind == ProtocolKind::Http) {
        handled = patch_engine.apply_transport_patch(plaintext_payload, "https-http", direction);
    }

    return handled;
}

std::uint16_t HttpsMitmProxy::allocate_local_port() {
    SOCKET probe_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (probe_socket == INVALID_SOCKET) {
        return 0;
    }

    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = 0;

    if (bind(probe_socket, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) == SOCKET_ERROR) {
        close_socket_if_valid(probe_socket);
        return 0;
    }

    int endpoint_length = sizeof(endpoint);
    if (getsockname(probe_socket, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_length) == SOCKET_ERROR) {
        close_socket_if_valid(probe_socket);
        return 0;
    }

    const std::uint16_t allocated_port = ntohs(endpoint.sin_port);
    close_socket_if_valid(probe_socket);
    return allocated_port;
}

SOCKET HttpsMitmProxy::connect_local_port(std::uint16_t port) {
    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = htons(port);

    for (int attempt = 0; attempt < 30; ++attempt) {
        if (connect(socket_handle, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) == 0) {
            return socket_handle;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    close_socket_if_valid(socket_handle);
    return INVALID_SOCKET;
}

bool HttpsMitmProxy::run_tls_mitm_session(SOCKET client_socket, const std::string& upstream_host, std::uint16_t upstream_port, ProtocolManager& protocol_manager, PatchEngine& patch_engine) const {
    std::filesystem::path leaf_cert_path;
    std::filesystem::path leaf_key_path;
    if (!ensure_leaf_certificate_for_host(upstream_host, leaf_cert_path, leaf_key_path)) {
        logger_.error("tls mitm leaf certificate prepare failed");
        return false;
    }

    const std::uint16_t local_tls_port = allocate_local_port();
    if (local_tls_port == 0) {
        logger_.error("tls mitm allocate local port failed");
        return false;
    }

    OpenSslProcess tls_server_process;
    std::string process_error;
    const std::string tls_server_command =
        quote_argument(config_.openssl_bin_path) +
        " s_server -quiet -accept " + std::to_string(local_tls_port) +
        " -cert " + quote_argument(leaf_cert_path.string()) +
        " -key " + quote_argument(leaf_key_path.string()) +
        " -servername 127.0.0.1";
    if (!tls_server_process.start(tls_server_command, process_error)) {
        logger_.error("start openssl s_server failed: " + process_error);
        return false;
    }

    SOCKET tls_bridge_socket = connect_local_port(local_tls_port);
    if (tls_bridge_socket == INVALID_SOCKET) {
        logger_.error("connect local tls terminator failed");
        tls_server_process.stop();
        return false;
    }

    OpenSslProcess tls_client_process;
    const std::string tls_client_command =
        quote_argument(config_.openssl_bin_path) +
        " s_client -quiet -connect " + upstream_host + ":" + std::to_string(upstream_port) +
        " -servername " + upstream_host;
    if (!tls_client_process.start(tls_client_command, process_error)) {
        logger_.error("start openssl s_client failed: " + process_error);
        close_socket_if_valid(tls_bridge_socket);
        tls_server_process.stop();
        return false;
    }

    std::atomic_bool stop_requested = false;

    std::jthread client_to_server_thread([&]() {
        relay_socket_stream(client_socket, tls_bridge_socket, stop_requested);
    });

    std::jthread server_to_client_thread([&]() {
        relay_socket_stream(tls_bridge_socket, client_socket, stop_requested);
    });

    std::jthread outbound_plaintext_thread([&]() {
        std::string read_error;
        std::string payload;
        while (!stop_requested.load() && tls_server_process.read_stdout(payload, read_error)) {
            patch_https_plaintext_http(payload, "outbound", protocol_manager, patch_engine);

            std::string write_error;
            if (!tls_client_process.write_stdin(payload.data(), payload.size(), write_error)) {
                logger_.warn("tls mitm outbound write failed: " + write_error);
                break;
            }
        }

        tls_client_process.close_stdin();
        stop_requested.store(true);
    });

    std::jthread inbound_plaintext_thread([&]() {
        std::string read_error;
        std::string payload;
        while (!stop_requested.load() && tls_client_process.read_stdout(payload, read_error)) {
            patch_https_plaintext_http(payload, "inbound", protocol_manager, patch_engine);

            std::string write_error;
            if (!tls_server_process.write_stdin(payload.data(), payload.size(), write_error)) {
                logger_.warn("tls mitm inbound write failed: " + write_error);
                break;
            }
        }

        tls_server_process.close_stdin();
        stop_requested.store(true);
    });

    while (!stop_requested.load()) {
        if (!tls_server_process.is_running() || !tls_client_process.is_running()) {
            stop_requested.store(true);
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    shutdown(client_socket, SD_BOTH);
    shutdown(tls_bridge_socket, SD_BOTH);
    close_socket_if_valid(tls_bridge_socket);

    tls_server_process.stop();
    tls_client_process.stop();

    logger_.info("tls mitm session ended for " + upstream_host + ":" + std::to_string(upstream_port));
    return true;
}

}  // namespace network_proxy
