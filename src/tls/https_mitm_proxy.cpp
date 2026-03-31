#include "tls/https_mitm_proxy.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "patch/patch_engine.h"
#include "protocol/protocol_detector.h"
#include "protocol/protocol_manager.h"
#include "tls/certificate_manager.h"

namespace network_proxy {

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

    const std::size_t extensions_end = std::min(offset + extensions_length, size);
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
            const std::size_t sni_end = std::min(sni_offset + sni_list_length, offset + extension_length);

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

}  // namespace network_proxy
