#include "rules/rule_engine.h"

#include <cctype>
#include <fstream>
#include <optional>

namespace network_proxy {

namespace {

std::string strip_comment(std::string_view line) {
    const std::size_t comment_pos = line.find('#');
    if (comment_pos == std::string_view::npos) {
        return std::string(line);
    }

    return std::string(line.substr(0, comment_pos));
}

std::optional<std::pair<std::string, std::string>> split_key_value(std::string_view line) {
    const std::size_t equal_pos = line.find('=');
    if (equal_pos == std::string_view::npos) {
        return std::nullopt;
    }

    return std::make_pair(std::string(line.substr(0, equal_pos)), std::string(line.substr(equal_pos + 1)));
}

}  // namespace

bool RuleEngine::load_from_file(const std::filesystem::path& rules_file_path, std::string& error_message) {
    rules_.clear();

    std::ifstream input(rules_file_path);
    if (!input.is_open()) {
        error_message = "cannot open rules file: " + rules_file_path.string();
        return false;
    }

    RuleDefinition current_rule;
    bool in_rule = false;

    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const std::string no_comment = strip_comment(line);
        const std::string trimmed = trim(no_comment);
        if (trimmed.empty()) {
            continue;
        }

        if (!in_rule) {
            if (!trimmed.starts_with("rule ")) {
                error_message = "expected rule declaration at line " + std::to_string(line_number);
                return false;
            }

            std::string rest = trim(trimmed.substr(5));
            if (!rest.ends_with('{')) {
                error_message = "expected '{' at rule declaration line " + std::to_string(line_number);
                return false;
            }

            rest.pop_back();
            rest = trim(rest);
            rest = unquote(rest);
            if (rest.empty()) {
                error_message = "rule name is empty at line " + std::to_string(line_number);
                return false;
            }

            current_rule = RuleDefinition{};
            current_rule.name = rest;
            in_rule = true;
            continue;
        }

        if (trimmed == "}") {
            rules_.push_back(current_rule);
            current_rule = RuleDefinition{};
            in_rule = false;
            continue;
        }

        const auto key_value = split_key_value(trimmed);
        if (!key_value.has_value()) {
            error_message = "expected key=value at line " + std::to_string(line_number);
            return false;
        }

        const std::string key = trim(key_value->first);
        const std::string value = unquote(trim(key_value->second));

        if (key == "when.protocol") {
            current_rule.when.protocol = to_lower(value);
            continue;
        }
        if (key == "when.direction") {
            current_rule.when.direction = to_lower(value);
            continue;
        }
        if (key == "when.host_contains") {
            current_rule.when.host_contains = to_lower(value);
            continue;
        }
        if (key == "when.method") {
            current_rule.when.method = to_lower(value);
            continue;
        }
        if (key == "when.path_contains") {
            current_rule.when.path_contains = to_lower(value);
            continue;
        }
        if (key == "when.process") {
            current_rule.when.process_name = to_lower(value);
            continue;
        }
        if (key == "when.remote_port") {
            std::uint16_t parsed_port = 0;
            if (!parse_u16(value, parsed_port)) {
                error_message = "invalid when.remote_port at line " + std::to_string(line_number);
                return false;
            }
            current_rule.when.remote_port = parsed_port;
            continue;
        }

        if (key == "action.text_find") {
            current_rule.action.text_find = value;
            continue;
        }
        if (key == "action.text_replace") {
            current_rule.action.text_replace = value;
            continue;
        }
        if (key == "action.hex_find") {
            current_rule.action.hex_find = value;
            continue;
        }
        if (key == "action.hex_replace") {
            current_rule.action.hex_replace = value;
            continue;
        }
        if (key == "action.body_find") {
            current_rule.action.body_find = value;
            continue;
        }
        if (key == "action.body_replace") {
            current_rule.action.body_replace = value;
            continue;
        }
        if (key.starts_with("action.header_set.")) {
            const std::string header_name = key.substr(std::string("action.header_set.").size());
            if (header_name.empty()) {
                error_message = "header name is empty at line " + std::to_string(line_number);
                return false;
            }

            current_rule.action.header_set[header_name] = value;
            continue;
        }

        error_message = "unknown rule key at line " + std::to_string(line_number) + ": " + key;
        return false;
    }

    if (in_rule) {
        error_message = "unterminated rule block at end of file";
        return false;
    }

    return true;
}

bool RuleEngine::apply_transport(std::string& payload, const RuleMatchContext& context) const {
    bool changed = false;

    for (const auto& rule : rules_) {
        if (!matches(rule.when, context)) {
            continue;
        }

        if (!rule.action.text_find.empty()) {
            changed |= replace_all(payload, rule.action.text_find, rule.action.text_replace) > 0;
        }

        if (!rule.action.hex_find.empty()) {
            std::string find_bytes;
            std::string replace_bytes;
            if (decode_hex_string(rule.action.hex_find, find_bytes)
                && decode_hex_string(rule.action.hex_replace, replace_bytes)
                && !find_bytes.empty()) {
                changed |= replace_all(payload, find_bytes, replace_bytes) > 0;
            }
        }
    }

    return changed;
}

bool RuleEngine::apply_http_request(HttpRequest& request, const RuleMatchContext& context) const {
    bool changed = false;

    for (const auto& rule : rules_) {
        if (!matches(rule.when, context)) {
            continue;
        }

        for (const auto& [name, value] : rule.action.header_set) {
            const auto existing = request.headers.find(name);
            if (existing == request.headers.end() || existing->second != value) {
                request.headers[name] = value;
                changed = true;
            }
        }

        if (!rule.action.body_find.empty()) {
            changed |= replace_all(request.body, rule.action.body_find, rule.action.body_replace) > 0;
        }

        if (!rule.action.text_find.empty()) {
            changed |= replace_all(request.body, rule.action.text_find, rule.action.text_replace) > 0;
        }
    }

    return changed;
}

bool RuleEngine::apply_http_response(HttpResponse& response, const RuleMatchContext& context) const {
    bool changed = false;

    for (const auto& rule : rules_) {
        if (!matches(rule.when, context)) {
            continue;
        }

        for (const auto& [name, value] : rule.action.header_set) {
            const auto existing = response.headers.find(name);
            if (existing == response.headers.end() || existing->second != value) {
                response.headers[name] = value;
                changed = true;
            }
        }

        if (!rule.action.body_find.empty()) {
            changed |= replace_all(response.body, rule.action.body_find, rule.action.body_replace) > 0;
        }

        if (!rule.action.text_find.empty()) {
            changed |= replace_all(response.body, rule.action.text_find, rule.action.text_replace) > 0;
        }
    }

    return changed;
}

std::size_t RuleEngine::rule_count() const {
    return rules_.size();
}

bool RuleEngine::matches(const RuleCondition& condition, const RuleMatchContext& context) {
    if (!condition.protocol.empty() && condition.protocol != "any" && condition.protocol != to_lower(context.protocol)) {
        return false;
    }

    if (!condition.direction.empty() && condition.direction != "any" && condition.direction != to_lower(context.direction)) {
        return false;
    }

    if (!condition.host_contains.empty()) {
        const std::string host = to_lower(context.host);
        if (host.find(condition.host_contains) == std::string::npos) {
            return false;
        }
    }

    if (!condition.method.empty() && condition.method != to_lower(context.method)) {
        return false;
    }

    if (!condition.path_contains.empty()) {
        const std::string path = to_lower(context.path);
        if (path.find(condition.path_contains) == std::string::npos) {
            return false;
        }
    }

    if (!condition.process_name.empty() && condition.process_name != to_lower(context.process_name)) {
        return false;
    }

    if (condition.remote_port != 0 && condition.remote_port != context.remote_port) {
        return false;
    }

    return true;
}

std::size_t RuleEngine::replace_all(std::string& source, std::string_view find_text, std::string_view replace_text) {
    if (find_text.empty()) {
        return 0;
    }

    std::size_t count = 0;
    std::size_t offset = 0;
    while ((offset = source.find(find_text, offset)) != std::string::npos) {
        source.replace(offset, find_text.size(), replace_text);
        offset += replace_text.size();
        ++count;
    }

    return count;
}

std::string RuleEngine::to_lower(std::string_view text) {
    std::string output(text);
    for (char& ch : output) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return output;
}

std::string RuleEngine::trim(std::string_view text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }

    std::size_t end = text.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }

    return std::string(text.substr(begin, end - begin));
}

std::string RuleEngine::unquote(std::string_view text) {
    if (text.size() >= 2 && ((text.front() == '"' && text.back() == '"') || (text.front() == '\'' && text.back() == '\''))) {
        return std::string(text.substr(1, text.size() - 2));
    }

    return std::string(text);
}

bool RuleEngine::parse_u16(std::string_view text, std::uint16_t& value) {
    try {
        const auto parsed = std::stoul(std::string(text));
        if (parsed > 65535) {
            return false;
        }

        value = static_cast<std::uint16_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool RuleEngine::decode_hex_string(std::string_view text, std::string& out_bytes) {
    out_bytes.clear();

    std::string normalized;
    normalized.reserve(text.size());
    for (const char ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == '-') {
            continue;
        }
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    if (normalized.starts_with("0x")) {
        normalized = normalized.substr(2);
    }

    if (normalized.empty()) {
        return true;
    }

    if ((normalized.size() % 2) != 0) {
        return false;
    }

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }
        return -1;
    };

    out_bytes.reserve(normalized.size() / 2);
    for (std::size_t index = 0; index < normalized.size(); index += 2) {
        const int high = nibble(normalized[index]);
        const int low = nibble(normalized[index + 1]);
        if (high < 0 || low < 0) {
            return false;
        }

        out_bytes.push_back(static_cast<char>((high << 4) | low));
    }

    return true;
}

}  // namespace network_proxy
