#pragma once

#include <cstdint>
#include <optional>
#include "config/app_config.h"
#include "logging/logger.h"
#include "protocol/http_types.h"
#include "rules/rule_engine.h"

namespace network_proxy {

class PatchEngine {
public:
    PatchEngine(const AppConfig& config, Logger& logger);

    void set_rule_engine(const RuleEngine* rule_engine);

    bool apply_request_patch(HttpRequest& request, const RuleMatchContext* context = nullptr) const;
    bool apply_response_patch(HttpResponse& response, const RuleMatchContext* context = nullptr) const;
    bool apply_transport_patch(std::string& payload, std::string_view protocol, std::string_view direction, const RuleMatchContext* context = nullptr) const;

private:
    static std::size_t replace_all(std::string& payload, std::string_view find_text, std::string_view replace_text);
    static std::optional<std::string> decode_hex_string(std::string_view value);
    static std::string normalize_hex_string(std::string_view value);

    const AppConfig& config_;
    Logger& logger_;
    const RuleEngine* rule_engine_ = nullptr;
};

}  // namespace network_proxy
