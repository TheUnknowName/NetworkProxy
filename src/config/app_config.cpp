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

        if (full_key == "listen.host") {
            listen_host = value;
            continue;
        }

        if (full_key == "listen.port") {
            try {
                listen_port = static_cast<std::uint16_t>(std::stoul(value));
            } catch (...) {
                error_message = "invalid listen.port at line " + std::to_string(line_number);
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
    }

    return true;
}

}  // namespace network_proxy
