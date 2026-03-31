#include "config/app_config.h"

#include <fstream>
#include <string>

#include "common/string_utils.h"

namespace network_proxy {

namespace {

bool parse_bool(std::string_view value, bool& result) {
    const std::string normalized = to_lower_copy(trim_copy(value));
    if (normalized == "true") {
        result = true;
        return true;
    }

    if (normalized == "false") {
        result = false;
        return true;
    }

    return false;
}

bool parse_u16(std::string_view value, std::uint16_t& result) {
    try {
        const auto numeric_value = std::stoul(trim_copy(value));
        if (numeric_value > 65535) {
            return false;
        }

        result = static_cast<std::uint16_t>(numeric_value);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_u32(std::string_view value, std::uint32_t& result) {
    try {
        result = static_cast<std::uint32_t>(std::stoul(trim_copy(value)));
        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace

bool AppConfig::load_from_file(const std::filesystem::path& config_path, std::string& error_message) {
    std::ifstream input_stream(config_path);
    if (!input_stream.is_open()) {
        error_message = "cannot open file: " + config_path.string();
        return false;
    }

    std::string section_name;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input_stream, line)) {
        ++line_number;

        const std::string trimmed_line = trim_copy(line);
        if (trimmed_line.empty() || trimmed_line.starts_with('#')) {
            continue;
        }

        if (trimmed_line.ends_with(':') && trimmed_line.find(' ') == std::string::npos) {
            section_name = trim_copy(trimmed_line.substr(0, trimmed_line.size() - 1));
            continue;
        }

        const auto key_value = split_once(trimmed_line, ':');
        if (!key_value.has_value()) {
            error_message = "invalid config line at " + std::to_string(line_number);
            return false;
        }

        const std::string key = trim_copy(key_value->first);
        const std::string value = trim_copy(key_value->second);
        const std::string full_key = section_name.empty() ? key : section_name + "." + key;

        if (full_key == "capture.enabled") {
            if (!parse_bool(value, capture_enabled)) {
                error_message = "invalid capture.enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "capture.use_windivert") {
            if (!parse_bool(value, use_windivert)) {
                error_message = "invalid capture.use_windivert at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "capture.windivert_filter") {
            windivert_filter = value;
            continue;
        }

        if (full_key == "tcp.enabled") {
            if (!parse_bool(value, tcp_enabled)) {
                error_message = "invalid tcp.enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "tcp.listen_host") {
            tcp_listen_host = value;
            continue;
        }

        if (full_key == "tcp.listen_port") {
            if (!parse_u16(value, tcp_listen_port)) {
                error_message = "invalid tcp.listen_port at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "tcp.upstream_host") {
            tcp_upstream_host = value;
            continue;
        }

        if (full_key == "tcp.upstream_port") {
            if (!parse_u16(value, tcp_upstream_port)) {
                error_message = "invalid tcp.upstream_port at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "udp.enabled") {
            if (!parse_bool(value, udp_enabled)) {
                error_message = "invalid udp.enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "udp.listen_host") {
            udp_listen_host = value;
            continue;
        }

        if (full_key == "udp.listen_port") {
            if (!parse_u16(value, udp_listen_port)) {
                error_message = "invalid udp.listen_port at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "udp.upstream_host") {
            udp_upstream_host = value;
            continue;
        }

        if (full_key == "udp.upstream_port") {
            if (!parse_u16(value, udp_upstream_port)) {
                error_message = "invalid udp.upstream_port at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "runtime.log_level") {
            log_level = to_lower_copy(value);
            continue;
        }

        if (full_key == "runtime.dry_run") {
            if (!parse_bool(value, dry_run)) {
                error_message = "invalid runtime.dry_run at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "runtime.max_runtime_seconds") {
            if (!parse_u32(value, max_runtime_seconds)) {
                error_message = "invalid runtime.max_runtime_seconds at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "protocol.enabled") {
            if (!parse_bool(value, protocol_adapter_enabled)) {
                error_message = "invalid protocol.enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "protocol.http_enabled") {
            if (!parse_bool(value, http_adapter_enabled)) {
                error_message = "invalid protocol.http_enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "https_mitm.enabled") {
            if (!parse_bool(value, https_mitm_enabled)) {
                error_message = "invalid https_mitm.enabled at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "https_mitm.ca_cert_path") {
            https_ca_cert_path = value;
            continue;
        }

        if (full_key == "https_mitm.ca_key_path") {
            https_ca_key_path = value;
            continue;
        }

        if (full_key == "https_mitm.ca_subject_name") {
            https_ca_subject_name = value;
            continue;
        }

        if (full_key == "https_mitm.install_to_current_user") {
            if (!parse_bool(value, https_install_to_current_user)) {
                error_message = "invalid https_mitm.install_to_current_user at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "https_mitm.cert_cache_dir") {
            https_cert_cache_dir = value;
            continue;
        }

        if (full_key == "https_mitm.openssl_bin_path") {
            openssl_bin_path = value;
            continue;
        }

        if (full_key == "https_mitm.plaintext_test_mode") {
            if (!parse_bool(value, https_plaintext_test_mode)) {
                error_message = "invalid https_mitm.plaintext_test_mode at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "patch.add_proxy_header") {
            if (!parse_bool(value, add_proxy_header)) {
                error_message = "invalid patch.add_proxy_header at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "patch.append_debug_suffix") {
            if (!parse_bool(value, append_debug_suffix)) {
                error_message = "invalid patch.append_debug_suffix at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "patch.enable_text_patch") {
            if (!parse_bool(value, enable_text_patch)) {
                error_message = "invalid patch.enable_text_patch at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "patch.enable_hex_patch") {
            if (!parse_bool(value, enable_hex_patch)) {
                error_message = "invalid patch.enable_hex_patch at line " + std::to_string(line_number);
                return false;
            }
            continue;
        }

        if (full_key == "patch.outbound_find") {
            outbound_find = value;
            continue;
        }

        if (full_key == "patch.outbound_replace") {
            outbound_replace = value;
            continue;
        }

        if (full_key == "patch.inbound_find") {
            inbound_find = value;
            continue;
        }

        if (full_key == "patch.inbound_replace") {
            inbound_replace = value;
            continue;
        }

        if (full_key == "patch.outbound_find_hex") {
            outbound_find_hex = value;
            continue;
        }

        if (full_key == "patch.outbound_replace_hex") {
            outbound_replace_hex = value;
            continue;
        }

        if (full_key == "patch.inbound_find_hex") {
            inbound_find_hex = value;
            continue;
        }

        if (full_key == "patch.inbound_replace_hex") {
            inbound_replace_hex = value;
            continue;
        }
    }

    return true;
}

}  // namespace network_proxy
