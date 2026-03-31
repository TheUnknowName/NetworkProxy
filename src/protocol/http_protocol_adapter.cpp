#include "protocol/http_protocol_adapter.h"

#include <cctype>
#include <sstream>
#include <string>
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
    if (starts_with_ignore_case(head, "HTTP/")) {
        HttpResponse response;
        response.body = body;
        patch_engine.apply_response_patch(response);
        if (response.body != body) {
            body = response.body;
            changed = true;
        }
    } else {
        HttpRequest request;
        request.body = body;
        patch_engine.apply_request_patch(request);
        if (request.body != body) {
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
