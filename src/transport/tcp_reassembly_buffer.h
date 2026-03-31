#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace network_proxy {

class TcpReassemblyBuffer {
public:
    void append(std::string_view chunk);
    std::size_t size() const;
    bool empty() const;
    std::string_view view() const;
    std::string take_all();
    bool try_take_http_message(std::string& message);

private:
    std::size_t parse_content_length(std::string_view headers) const;

    std::string buffer_;
};

}  // namespace network_proxy
