#pragma once

#include <string_view>

namespace network_proxy {

enum class ProtocolKind {
    Unknown,
    Http,
    Https,
};

ProtocolKind detect_protocol_kind(std::string_view payload);

}  // namespace network_proxy
