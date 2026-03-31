#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace network_proxy {

struct AppConfig {
    bool capture_enabled = false;
    bool use_wfp = false;
    bool use_windivert = false;
    std::string wfp_filter = "ip and (tcp or udp)";
    bool wfp_redirect_enabled = false;
    bool wfp_redirect_allow_startup_fallback = true;
    bool wfp_redirect_allow_runtime_fallback = true;
    std::string wfp_callout_channel = "local://network_proxy_callout";
    std::string wfp_redirect_filter = "ip and (tcp or udp)";
    std::string windivert_filter = "ip and (tcp or udp)";

    bool tcp_enabled = true;
    std::string tcp_listen_host = "127.0.0.1";
    std::uint16_t tcp_listen_port = 18080;
    std::string tcp_upstream_host = "127.0.0.1";
    std::uint16_t tcp_upstream_port = 28080;

    bool udp_enabled = true;
    std::string udp_listen_host = "127.0.0.1";
    std::uint16_t udp_listen_port = 18081;
    std::string udp_upstream_host = "127.0.0.1";
    std::uint16_t udp_upstream_port = 28081;

    std::string log_level = "info";
    bool dry_run = true;
    std::uint32_t max_runtime_seconds = 0;

    bool protocol_adapter_enabled = true;
    bool http_adapter_enabled = true;

    bool rules_enabled = true;
    std::string rules_file_path = "config/rules.dsl";

    bool https_mitm_enabled = false;
    std::string https_ca_cert_path;
    std::string https_ca_key_path;
    std::string https_ca_subject_name = "NetworkProxy Local CA";
    bool https_install_to_current_user = true;
    std::string https_cert_cache_dir = "cert/cache";
    std::string openssl_bin_path = "openssl";
    bool https_plaintext_test_mode = false;

    bool add_proxy_header = true;
    bool append_debug_suffix = true;
    bool enable_text_patch = true;
    bool enable_hex_patch = false;

    std::string outbound_find;
    std::string outbound_replace;
    std::string inbound_find;
    std::string inbound_replace;
    std::string outbound_find_hex;
    std::string outbound_replace_hex;
    std::string inbound_find_hex;
    std::string inbound_replace_hex;

    bool load_from_file(const std::filesystem::path& config_path, std::string& error_message);
};

}  // namespace network_proxy
