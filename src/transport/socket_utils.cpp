#include "transport/socket_utils.h"

#include <array>
#include <cstring>
#include <string>

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

bool resolve_endpoint(const std::string& host, std::uint16_t port, sockaddr_storage& endpoint, int& endpoint_length, int socket_type) {
    endpoint = {};
    endpoint_length = 0;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_protocol = (socket_type == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string port_text = std::to_string(port);
    const int get_result = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result);
    if (get_result != 0 || result == nullptr) {
        return false;
    }

    bool ok = false;
    for (addrinfo* item = result; item != nullptr; item = item->ai_next) {
        if (item->ai_addr == nullptr) {
            continue;
        }

        if (item->ai_family != AF_INET && item->ai_family != AF_INET6) {
            continue;
        }

        if (item->ai_addrlen > static_cast<int>(sizeof(sockaddr_storage))) {
            continue;
        }

        std::memcpy(&endpoint, item->ai_addr, static_cast<std::size_t>(item->ai_addrlen));
        endpoint_length = item->ai_addrlen;
        ok = true;
        break;
    }

    freeaddrinfo(result);
    return ok;
}

std::string endpoint_ip_to_string(const sockaddr* endpoint) {
    if (endpoint == nullptr) {
        return "";
    }

    std::array<char, INET6_ADDRSTRLEN> text{};
    if (endpoint->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(endpoint);
        if (InetNtopA(AF_INET, const_cast<in_addr*>(&ipv4->sin_addr), text.data(), static_cast<DWORD>(text.size())) == nullptr) {
            return "";
        }
        return std::string(text.data());
    }

    if (endpoint->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(endpoint);
        if (InetNtopA(AF_INET6, const_cast<in6_addr*>(&ipv6->sin6_addr), text.data(), static_cast<DWORD>(text.size())) == nullptr) {
            return "";
        }
        return std::string(text.data());
    }

    return "";
}

std::uint16_t endpoint_port(const sockaddr* endpoint) {
    if (endpoint == nullptr) {
        return 0;
    }

    if (endpoint->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(endpoint);
        return ntohs(ipv4->sin_port);
    }

    if (endpoint->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(endpoint);
        return ntohs(ipv6->sin6_port);
    }

    return 0;
}

}  // namespace network_proxy
