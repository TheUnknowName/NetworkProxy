#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace network_proxy {

using HeaderMap = std::unordered_map<std::string, std::string>;

struct HttpRequest {
    std::string method;
    std::string target;
    HeaderMap headers;
    std::string body;
};

struct HttpResponse {
    std::uint16_t status_code = 200;
    HeaderMap headers;
    std::string body;
};

}  // namespace network_proxy
