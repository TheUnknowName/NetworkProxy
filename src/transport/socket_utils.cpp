#include "transport/socket_utils.h"

#include <WS2tcpip.h>

namespace network_proxy {

bool set_socket_timeout(SOCKET socket_handle, int timeout_milliseconds) {
    const DWORD timeout_value = static_cast<DWORD>(timeout_milliseconds);
    return setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_value), sizeof(timeout_value)) == 0
        && setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_value), sizeof(timeout_value)) == 0;
}

bool send_all(SOCKET socket_handle, const char* data, int data_length) {
    int total_sent = 0;
    while (total_sent < data_length) {
        const int sent = send(socket_handle, data + total_sent, data_length - total_sent, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return false;
        }

        total_sent += sent;
    }

    return true;
}

std::string describe_socket_error() {
    return std::to_string(WSAGetLastError());
}

bool resolve_ipv4_endpoint(const std::string& host, std::uint16_t port, sockaddr_in& endpoint) {
    endpoint = {};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);

    const int parse_result = InetPtonA(AF_INET, host.c_str(), &endpoint.sin_addr);
    return parse_result == 1;
}

}  // namespace network_proxy
