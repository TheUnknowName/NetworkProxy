#include "protocol/protocol_detector.h"

#include <algorithm>
#include <array>
#include <string>

namespace network_proxy {

ProtocolKind detect_protocol_kind(std::string_view payload) {
    if (payload.empty()) {
        return ProtocolKind::Unknown;
    }

    constexpr std::array<std::string_view, 9> k_http_request_methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT "};

    for (const auto method_prefix : k_http_request_methods) {
        if (payload.starts_with(method_prefix)) {
            return ProtocolKind::Http;
        }
    }

    if (payload.starts_with("HTTP/1.0 ") || payload.starts_with("HTTP/1.1 ")) {
        return ProtocolKind::Http;
    }

    if (payload.size() >= 3) {
        const unsigned char first_byte = static_cast<unsigned char>(payload[0]);
        const unsigned char second_byte = static_cast<unsigned char>(payload[1]);
        if (first_byte == 0x16 && second_byte == 0x03) {
            return ProtocolKind::Https;
        }
    }

    return ProtocolKind::Unknown;
}

}  // namespace network_proxy
