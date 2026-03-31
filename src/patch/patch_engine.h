#pragma once

#include <cstdint>
#include <optional>
#include "config/app_config.h"
#include "logging/logger.h"
#include "protocol/http_types.h"

namespace network_proxy {

class PatchEngine {
public:
    PatchEngine(const AppConfig& config, Logger& logger);

    void apply_request_patch(HttpRequest& request) const;
    void apply_response_patch(HttpResponse& response) const;
    bool apply_transport_patch(std::string& payload, std::string_view protocol, std::string_view direction) const;

private:
    static std::size_t replace_all(std::string& payload, std::string_view find_text, std::string_view replace_text);
    static std::optional<std::string> decode_hex_string(std::string_view value);
    static std::string normalize_hex_string(std::string_view value);

    const AppConfig& config_;
    Logger& logger_;
};

}  // namespace network_proxy
