#include "protocol/http_protocol_adapter.h"

#include <cctype>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "protocol/http_types.h"

namespace network_proxy {

namespace {

bool starts_with_ignore_case(std::string_view value, std::string_view prefix) {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        const char left = static_cast<char>(std::tolower(static_cast<unsigned char>(value[index])));
        const char right = static_cast<char>(std::tolower(static_cast<unsigned char>(prefix[index])));
        if (left != right) {
            return false;
        }
    }

    return true;
}

bool split_http_message(std::string_view payload, std::string& head, std::string& body) {
    const std::size_t delimiter_position = payload.find("\r\n\r\n");
    if (delimiter_position == std::string_view::npos) {
        return false;
    }

    head = std::string(payload.substr(0, delimiter_position));
    body = std::string(payload.substr(delimiter_position + 4));
    return true;
}

std::vector<std::string> split_lines(std::string_view text) {
    std::vector<std::string> lines;
    std::stringstream stream{std::string(text)};
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

HeaderMap parse_headers(const std::vector<std::string>& lines, std::size_t start_index) {
    HeaderMap headers;
    for (std::size_t i = start_index; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        const std::size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        std::string name = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        headers[name] = value;
    }

    return headers;
}

std::string get_header_value(const HeaderMap& headers, const std::string& name) {
    for (const auto& [header_name, header_value] : headers) {
        if (starts_with_ignore_case(header_name, name)) {
            return header_value;
        }
    }

    return "";
}

bool parse_request_start_line(const std::string& line, HttpRequest& request) {
    const std::size_t first_space = line.find(' ');
    if (first_space == std::string::npos) {
        return false;
    }

    const std::size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string::npos) {
        return false;
    }

    request.method = line.substr(0, first_space);
    request.target = line.substr(first_space + 1, second_space - first_space - 1);
    return true;
}

bool parse_response_start_line(const std::string& line, HttpResponse& response) {
    const std::size_t first_space = line.find(' ');
    if (first_space == std::string::npos) {
        return false;
    }

    const std::size_t second_space = line.find(' ', first_space + 1);
    const std::string status_part = second_space == std::string::npos ? line.substr(first_space + 1) : line.substr(first_space + 1, second_space - first_space - 1);
    try {
        response.status_code = static_cast<std::uint16_t>(std::stoul(status_part));
        return true;
    } catch (...) {
        return false;
    }
}

RuleMatchContext build_rule_context(const ProtocolContext& context, const HttpRequest* request, const HeaderMap& headers) {
    RuleMatchContext match_context;
    match_context.direction = context.direction;
    match_context.remote_port = context.remote_port;
    match_context.process_name = context.process_name;
    match_context.path = context.path;

    if (context.protocol_kind == ProtocolKind::Http) {
        match_context.protocol = "http";
    } else if (context.protocol_kind == ProtocolKind::Https) {
        match_context.protocol = "https";
    } else {
        match_context.protocol = "unknown";
    }

    if (request != nullptr) {
        match_context.method = request->method;
        if (!request->target.empty()) {
            match_context.path = request->target;
        }
    }

    match_context.host = context.host;
    if (match_context.host.empty()) {
        match_context.host = get_header_value(headers, "Host");
    }

    return match_context;
}

std::string rebuild_headers_with_content_length(std::string_view head, std::size_t body_size) {
    std::stringstream stream{std::string(head)};
    std::string line;
    std::vector<std::string> lines;
    bool has_content_length = false;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (starts_with_ignore_case(line, "Content-Length:")) {
            line = "Content-Length: " + std::to_string(body_size);
            has_content_length = true;
        }

        lines.push_back(line);
    }

    if (!has_content_length && !lines.empty()) {
        lines.push_back("Content-Length: " + std::to_string(body_size));
    }

    std::string rebuilt;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        rebuilt += lines[index];
        if (index + 1 < lines.size()) {
            rebuilt += "\r\n";
        }
    }

    return rebuilt;
}

std::string rebuild_head_from_model(const std::string& start_line, const HeaderMap& headers, std::size_t body_size) {
    std::string rebuilt = start_line;
    rebuilt += "\r\n";

    bool has_content_length = false;
    for (const auto& [name, value] : headers) {
        if (starts_with_ignore_case(name, "Content-Length")) {
            rebuilt += "Content-Length: " + std::to_string(body_size) + "\r\n";
            has_content_length = true;
            continue;
        }

        rebuilt += name + ": " + value + "\r\n";
    }

    if (!has_content_length) {
        rebuilt += "Content-Length: " + std::to_string(body_size) + "\r\n";
    }

    return rebuilt;
}

}  // namespace

bool HttpProtocolAdapter::can_handle(const ProtocolContext& context, std::string_view payload) const {
    if (context.protocol_kind != ProtocolKind::Http) {
        return false;
    }

    return payload.find("\r\n") != std::string_view::npos;
}

bool HttpProtocolAdapter::apply_patch(std::string& payload, const ProtocolContext& context, PatchEngine& patch_engine, const AppConfig& config, Logger& logger) const {
    std::string head;
    std::string body;
    if (!split_http_message(payload, head, body)) {
        return false;
    }

    bool changed = false;
    const std::vector<std::string> lines = split_lines(head);
    if (lines.empty()) {
        return false;
    }

    if (starts_with_ignore_case(lines[0], "HTTP/")) {
        HttpResponse response;
        parse_response_start_line(lines[0], response);
        response.headers = parse_headers(lines, 1);
        response.body = body;
        const RuleMatchContext match_context = build_rule_context(context, nullptr, response.headers);
        const bool patched = patch_engine.apply_response_patch(response, &match_context);
        if (patched) {
            head = rebuild_head_from_model(lines[0], response.headers, response.body.size());
            body = response.body;
            changed = true;
        }
    } else {
        HttpRequest request;
        if (!parse_request_start_line(lines[0], request)) {
            return false;
        }
        request.headers = parse_headers(lines, 1);
        request.body = body;
        const RuleMatchContext match_context = build_rule_context(context, &request, request.headers);
        const bool patched = patch_engine.apply_request_patch(request, &match_context);
        if (patched) {
            head = rebuild_head_from_model(lines[0], request.headers, request.body.size());
            body = request.body;
            changed = true;
        }
    }

    if (!changed) {
        return false;
    }

    const std::string rebuilt_head = rebuild_headers_with_content_length(head, body.size());
    payload = rebuilt_head + "\r\n\r\n" + body;

    logger.debug("http structured patch applied, direction=" + context.direction + ", add_proxy_header=" + std::string(config.add_proxy_header ? "true" : "false"));
    return true;
}

std::string HttpProtocolAdapter::adapter_name() const {
    return "http_protocol_adapter";
}

}  // namespace network_proxy
