#include "transport/tcp_reassembly_buffer.h"

#include <algorithm>
#include <cctype>
#include <ranges>
#include <string>

namespace network_proxy {

void TcpReassemblyBuffer::append(std::string_view chunk) {
    buffer_.append(chunk);
}

std::size_t TcpReassemblyBuffer::size() const {
    return buffer_.size();
}

bool TcpReassemblyBuffer::empty() const {
    return buffer_.empty();
}

std::string_view TcpReassemblyBuffer::view() const {
    return std::string_view(buffer_.data(), buffer_.size());
}

std::string TcpReassemblyBuffer::take_all() {
    std::string output;
    output.swap(buffer_);
    return output;
}

bool TcpReassemblyBuffer::try_take_http_message(std::string& message) {
    const std::size_t header_end = buffer_.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;
    }

    const std::string_view header_view(buffer_.data(), header_end + 4);
    const std::size_t content_length = parse_content_length(header_view);
    const std::size_t message_length = header_end + 4 + content_length;
    if (buffer_.size() < message_length) {
        return false;
    }

    message.assign(buffer_.data(), message_length);
    buffer_.erase(0, message_length);
    return true;
}

std::size_t TcpReassemblyBuffer::parse_content_length(std::string_view headers) const {
    constexpr std::string_view key = "content-length:";

    const auto to_lower = [](std::string_view source) {
        std::string output(source);
        std::ranges::transform(output, output.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return output;
    };

    const std::string lower_headers = to_lower(headers);
    const std::size_t key_position = lower_headers.find(key);
    if (key_position == std::string::npos) {
        return 0;
    }

    const std::size_t line_end = lower_headers.find("\r\n", key_position);
    if (line_end == std::string::npos) {
        return 0;
    }

    const std::size_t value_begin = key_position + key.size();
    const std::string value = lower_headers.substr(value_begin, line_end - value_begin);

    try {
        return static_cast<std::size_t>(std::stoull(value));
    } catch (...) {
        return 0;
    }
}

}  // namespace network_proxy
