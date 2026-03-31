#include "transport/tcp_proxy_server.h"

#include <cctype>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "protocol/protocol_detector.h"
#include "tls/https_mitm_proxy.h"
#include "transport/socket_utils.h"
#include "transport/tcp_reassembly_buffer.h"

namespace network_proxy {

namespace {

void close_socket_if_valid(SOCKET socket_handle) {
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
}

void shutdown_socket_pair(SOCKET source_socket, SOCKET target_socket) {
    shutdown(source_socket, SD_BOTH);
    shutdown(target_socket, SD_BOTH);
}

bool starts_with_ignore_case(std::string_view value, std::string_view prefix) {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        const char left = static_cast<char>(std::tolower(static_cast<unsigned char>(value[index])));
        const char right = static_cast<char>(std::tolower(static_cast<unsigned char>(prefix[index])));
        if (left != right) {
            return false;
        }
    }

    return true;
}

std::optional<std::pair<std::string, std::uint16_t>> parse_connect_authority(std::string_view http_request) {
    const std::size_t line_end = http_request.find("\r\n");
    if (line_end == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view first_line = http_request.substr(0, line_end);
    constexpr std::string_view prefix = "CONNECT ";
    if (!starts_with_ignore_case(first_line, prefix)) {
        return std::nullopt;
    }

    const std::size_t target_begin = prefix.size();
    const std::size_t target_end = first_line.find(' ', target_begin);
    if (target_end == std::string_view::npos || target_end <= target_begin) {
        return std::nullopt;
    }

    const std::string authority(first_line.substr(target_begin, target_end - target_begin));
    const std::size_t colon_position = authority.rfind(':');
    if (colon_position == std::string::npos) {
        return std::make_pair(authority, static_cast<std::uint16_t>(443));
    }

    const std::string host = authority.substr(0, colon_position);
    if (host.empty()) {
        return std::nullopt;
    }

    try {
        const std::uint16_t port = static_cast<std::uint16_t>(std::stoul(authority.substr(colon_position + 1)));
        return std::make_pair(host, port);
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

TcpProxyServer::TcpProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine, ProtocolManager& protocol_manager, HttpsMitmProxy& https_mitm_proxy)
    : config_(config), logger_(logger), patch_engine_(patch_engine), protocol_manager_(protocol_manager), https_mitm_proxy_(https_mitm_proxy) {
}

void TcpProxyServer::serve(std::atomic_bool& stop_requested) {
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        logger_.error("tcp listen socket create failed, error=" + describe_socket_error());
        stop_requested.store(true);
        return;
    }

    const bool timeout_set = set_socket_timeout(listen_socket, 500);
    if (!timeout_set) {
        logger_.warn("tcp listen socket timeout setup failed, error=" + describe_socket_error());
    }

    sockaddr_in listen_endpoint{};
    if (!resolve_ipv4_endpoint(config_.tcp_listen_host, config_.tcp_listen_port, listen_endpoint)) {
        logger_.error("tcp listen host parse failed: " + config_.tcp_listen_host);
        close_socket_if_valid(listen_socket);
        stop_requested.store(true);
        return;
    }

    const int reuse_address = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse_address), sizeof(reuse_address));

    if (bind(listen_socket, reinterpret_cast<const sockaddr*>(&listen_endpoint), sizeof(listen_endpoint)) == SOCKET_ERROR) {
        logger_.error("tcp bind failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        stop_requested.store(true);
        return;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        logger_.error("tcp listen failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        stop_requested.store(true);
        return;
    }

    logger_.info("tcp proxy listening on " + config_.tcp_listen_host + ":" + std::to_string(config_.tcp_listen_port));

    std::vector<std::thread> client_threads;
    while (!stop_requested.load()) {
        sockaddr_in client_endpoint{};
        int client_endpoint_length = sizeof(client_endpoint);
        SOCKET client_socket = accept(listen_socket, reinterpret_cast<sockaddr*>(&client_endpoint), &client_endpoint_length);
        if (client_socket == INVALID_SOCKET) {
            const int last_error = WSAGetLastError();
            if (last_error == WSAETIMEDOUT || last_error == WSAEWOULDBLOCK) {
                continue;
            }

            logger_.warn("tcp accept failed, error=" + std::to_string(last_error));
            continue;
        }

        client_threads.emplace_back([this, client_socket]() {
            handle_client(client_socket);
        });
    }

    close_socket_if_valid(listen_socket);

    for (auto& client_thread : client_threads) {
        if (client_thread.joinable()) {
            client_thread.join();
        }
    }
}

void TcpProxyServer::handle_client(SOCKET client_socket) const {
    set_socket_timeout(client_socket, 1000);

    std::string upstream_host = config_.tcp_upstream_host;
    std::uint16_t upstream_port = config_.tcp_upstream_port;

    char initial_buffer[8192];
    int initial_received = recv(client_socket, initial_buffer, sizeof(initial_buffer), 0);
    std::string initial_payload;
    if (initial_received > 0) {
        initial_payload.assign(initial_buffer, initial_buffer + initial_received);
    }

    bool is_connect_tunnel = false;
    bool force_https_plaintext_patch = false;
    if (!initial_payload.empty()) {
        const auto connect_target = parse_connect_authority(initial_payload);
        if (connect_target.has_value()) {
            is_connect_tunnel = true;
            upstream_host = connect_target->first;
            upstream_port = connect_target->second;
            logger_.info("connect tunnel target: " + upstream_host + ":" + std::to_string(upstream_port));
        }
    }

    if (is_connect_tunnel && config_.https_mitm_enabled && !config_.https_plaintext_test_mode) {
        const std::string connect_ok = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: network_proxy\r\n\r\n";
        if (!send_all(client_socket, connect_ok.data(), static_cast<int>(connect_ok.size()))) {
            close_socket_if_valid(client_socket);
            return;
        }

        https_mitm_proxy_.run_tls_mitm_session(client_socket, upstream_host, upstream_port, protocol_manager_, patch_engine_);
        close_socket_if_valid(client_socket);
        return;
    }

    SOCKET upstream_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (upstream_socket == INVALID_SOCKET) {
        logger_.error("tcp upstream socket create failed, error=" + describe_socket_error());
        close_socket_if_valid(client_socket);
        return;
    }

    set_socket_timeout(upstream_socket, 1000);

    sockaddr_in upstream_endpoint{};
    if (!resolve_ipv4_endpoint(upstream_host, upstream_port, upstream_endpoint)) {
        logger_.error("tcp upstream host parse failed: " + upstream_host);
        close_socket_if_valid(client_socket);
        close_socket_if_valid(upstream_socket);
        return;
    }

    if (connect(upstream_socket, reinterpret_cast<const sockaddr*>(&upstream_endpoint), sizeof(upstream_endpoint)) == SOCKET_ERROR) {
        logger_.error("tcp upstream connect failed, error=" + describe_socket_error());
        close_socket_if_valid(client_socket);
        close_socket_if_valid(upstream_socket);
        return;
    }

    logger_.info("tcp client connected, forwarding to " + upstream_host + ":" + std::to_string(upstream_port));

    if (is_connect_tunnel) {
        if (config_.https_mitm_enabled) {
            std::filesystem::path leaf_cert_path;
            std::filesystem::path leaf_key_path;
            if (!https_mitm_proxy_.ensure_leaf_certificate_for_host(upstream_host, leaf_cert_path, leaf_key_path)) {
                logger_.warn("dynamic certificate prepare failed for host: " + upstream_host);
            } else {
                logger_.info("dynamic certificate ready: " + leaf_cert_path.string());
            }
        }

        const std::string connect_ok = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: network_proxy\r\n\r\n";
        if (!send_all(client_socket, connect_ok.data(), static_cast<int>(connect_ok.size()))) {
            close_socket_if_valid(client_socket);
            close_socket_if_valid(upstream_socket);
            return;
        }

        force_https_plaintext_patch = config_.https_plaintext_test_mode;
    }

    auto pump = [this, force_https_plaintext_patch](SOCKET source_socket, SOCKET target_socket, const std::string& direction, std::string first_payload) {
        TcpReassemblyBuffer reassembly_buffer;
        bool protocol_decided = false;
        ProtocolKind protocol_kind = ProtocolKind::Unknown;

        auto patch_and_send = [this, &direction, &protocol_kind, force_https_plaintext_patch, target_socket](std::string payload) {
            if (force_https_plaintext_patch) {
                https_mitm_proxy_.patch_https_plaintext_http(payload, direction, protocol_manager_, patch_engine_);
                return send_all(target_socket, payload.data(), static_cast<int>(payload.size()));
            }

            ProtocolContext context;
            context.direction = direction;
            context.protocol_kind = protocol_kind;

            const bool structured_patched = protocol_manager_.patch_payload(payload, context);
            if (!structured_patched) {
                patch_engine_.apply_transport_patch(payload, "tcp", direction);
            }

            return send_all(target_socket, payload.data(), static_cast<int>(payload.size()));
        };

        if (!first_payload.empty()) {
            reassembly_buffer.append(first_payload);
        }

        char buffer[4096];
        for (;;) {
            if (reassembly_buffer.empty()) {
                const int received = recv(source_socket, buffer, sizeof(buffer), 0);
                if (received == 0) {
                    break;
                }

                if (received == SOCKET_ERROR) {
                    const int last_error = WSAGetLastError();
                    if (last_error == WSAETIMEDOUT || last_error == WSAEWOULDBLOCK) {
                        continue;
                    }
                    break;
                }

                reassembly_buffer.append(std::string_view(buffer, static_cast<std::size_t>(received)));
            }

            if (!protocol_decided) {
                protocol_kind = detect_protocol_kind(reassembly_buffer.view());
                if (protocol_kind != ProtocolKind::Unknown || reassembly_buffer.size() >= 32) {
                    protocol_decided = true;
                }
            }

            if (protocol_kind == ProtocolKind::Http) {
                std::string message;
                if (!reassembly_buffer.try_take_http_message(message)) {
                    if (reassembly_buffer.size() > 8192) {
                        std::string payload = reassembly_buffer.take_all();
                        if (!patch_and_send(std::move(payload))) {
                            return;
                        }
                    }
                    continue;
                }

                if (!patch_and_send(std::move(message))) {
                    return;
                }
                continue;
            }

            std::string payload = reassembly_buffer.take_all();
            if (!payload.empty() && !patch_and_send(std::move(payload))) {
                return;
            }
        }

        std::string tail = reassembly_buffer.take_all();
        if (!tail.empty()) {
            patch_and_send(std::move(tail));
        }
    };

    std::thread outbound_thread([&]() {
        std::string outbound_first_payload;
        if (!is_connect_tunnel && !initial_payload.empty()) {
            outbound_first_payload = initial_payload;
        }

        pump(client_socket, upstream_socket, "outbound", std::move(outbound_first_payload));
        shutdown_socket_pair(client_socket, upstream_socket);
    });

    std::thread inbound_thread([&]() {
        pump(upstream_socket, client_socket, "inbound", "");
        shutdown_socket_pair(upstream_socket, client_socket);
    });

    outbound_thread.join();
    inbound_thread.join();

    close_socket_if_valid(client_socket);
    close_socket_if_valid(upstream_socket);
    logger_.info("tcp client disconnected");
}

}  // namespace network_proxy
