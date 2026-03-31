#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace network_proxy {

struct AppConfig {
    std::string listen_host = "127.0.0.1";
    std::uint16_t listen_port = 18080;
    std::string log_level = "info";
    bool dry_run = true;
    bool add_proxy_header = true;
    bool append_debug_suffix = true;

    bool load_from_file(const std::filesystem::path& config_path, std::string& error_message);
};

}  // namespace network_proxy
