#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "protocol/http_types.h"

namespace network_proxy {

struct RuleMatchContext {
    std::string protocol;
    std::string direction;
    std::string host;
    std::string method;
    std::string path;
    std::string process_name;
    std::uint16_t remote_port = 0;
};

struct RuleCondition {
    std::string protocol;
    std::string direction;
    std::string host_contains;
    std::string method;
    std::string path_contains;
    std::string process_name;
    std::uint16_t remote_port = 0;
};

struct RuleAction {
    std::string text_find;
    std::string text_replace;
    std::string hex_find;
    std::string hex_replace;
    std::string body_find;
    std::string body_replace;
    std::unordered_map<std::string, std::string> header_set;
};

struct RuleDefinition {
    std::string name;
    RuleCondition when;
    RuleAction action;
};

class RuleEngine {
public:
    bool load_from_file(const std::filesystem::path& rules_file_path, std::string& error_message);

    bool apply_transport(std::string& payload, const RuleMatchContext& context) const;
    bool apply_http_request(HttpRequest& request, const RuleMatchContext& context) const;
    bool apply_http_response(HttpResponse& response, const RuleMatchContext& context) const;

    std::size_t rule_count() const;

private:
    static bool matches(const RuleCondition& condition, const RuleMatchContext& context);
    static std::size_t replace_all(std::string& source, std::string_view find_text, std::string_view replace_text);
    static std::string to_lower(std::string_view text);
    static std::string trim(std::string_view text);
    static std::string unquote(std::string_view text);
    static bool parse_u16(std::string_view text, std::uint16_t& value);

    static bool decode_hex_string(std::string_view text, std::string& out_bytes);

    std::vector<RuleDefinition> rules_;
};

}  // namespace network_proxy
