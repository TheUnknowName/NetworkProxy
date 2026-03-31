#include "patch/patch_engine.h"

#include <cctype>
#include <string>

namespace network_proxy {

PatchEngine::PatchEngine(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger) {
}

void PatchEngine::apply_request_patch(HttpRequest& request) const {
    if (config_.add_proxy_header) {
        request.headers["X-Network-Proxy"] = "network_proxy";
    }

    if (config_.append_debug_suffix && !request.body.empty()) {
        request.body += "\n[patched-by-network-proxy-request]";
    }

    logger_.debug("request patch applied");
}

void PatchEngine::apply_response_patch(HttpResponse& response) const {
    if (config_.add_proxy_header) {
        response.headers["X-Network-Proxy"] = "network_proxy";
    }

    if (config_.append_debug_suffix && !response.body.empty()) {
        response.body += "\n[patched-by-network-proxy-response]";
    }

    logger_.debug("response patch applied");
}

bool PatchEngine::apply_transport_patch(std::string& payload, std::string_view protocol, std::string_view direction) const {
    const bool is_outbound = direction == "outbound";
    std::size_t total_replace_count = 0;

    if (config_.enable_text_patch) {
        const std::string& find_text = is_outbound ? config_.outbound_find : config_.inbound_find;
        const std::string& replace_text = is_outbound ? config_.outbound_replace : config_.inbound_replace;

        if (!find_text.empty()) {
            total_replace_count += replace_all(payload, find_text, replace_text);
        }
    }

    if (config_.enable_hex_patch) {
        const std::string& find_hex = is_outbound ? config_.outbound_find_hex : config_.inbound_find_hex;
        const std::string& replace_hex = is_outbound ? config_.outbound_replace_hex : config_.inbound_replace_hex;

        const std::optional<std::string> find_bytes = decode_hex_string(find_hex);
        const std::optional<std::string> replace_bytes = decode_hex_string(replace_hex);
        if (find_bytes.has_value() && replace_bytes.has_value() && !find_bytes->empty()) {
            total_replace_count += replace_all(payload, *find_bytes, *replace_bytes);
        }
    }

    if (total_replace_count == 0) {
        return false;
    }

    logger_.info(std::string(protocol) + " " + std::string(direction) + " patch applied, replacements=" + std::to_string(total_replace_count));
    return true;
}

std::optional<std::string> PatchEngine::decode_hex_string(std::string_view value) {
    const std::string normalized = normalize_hex_string(value);
    if (normalized.empty()) {
        return std::string();
    }

    if ((normalized.size() % 2) != 0) {
        return std::nullopt;
    }

    std::string bytes;
    bytes.reserve(normalized.size() / 2);
    auto hex_to_nibble = [](char character) -> int {
        if (character >= '0' && character <= '9') {
            return character - '0';
        }
        if (character >= 'a' && character <= 'f') {
            return 10 + (character - 'a');
        }
        return -1;
    };

    for (std::size_t index = 0; index < normalized.size(); index += 2) {
        const int high = hex_to_nibble(normalized[index]);
        const int low = hex_to_nibble(normalized[index + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }

        const char byte = static_cast<char>((high << 4) | low);
        bytes.push_back(byte);
    }

    return bytes;
}

std::string PatchEngine::normalize_hex_string(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (const char character : value) {
        if (std::isspace(static_cast<unsigned char>(character)) != 0 || character == '-') {
            continue;
        }

        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }

    if (normalized.starts_with("0x")) {
        normalized = normalized.substr(2);
    }

    return normalized;
}

std::size_t PatchEngine::replace_all(std::string& payload, std::string_view find_text, std::string_view replace_text) {
    if (find_text.empty()) {
        return 0;
    }

    std::size_t count = 0;
    std::size_t search_position = 0;
    while ((search_position = payload.find(find_text, search_position)) != std::string::npos) {
        payload.replace(search_position, find_text.size(), replace_text);
        search_position += replace_text.size();
        ++count;
    }

    return count;
}

}  // namespace network_proxy
