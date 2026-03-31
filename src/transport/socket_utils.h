#pragma once

#include <cstdint>
#include <string>

#include <WinSock2.h>

namespace network_proxy {

bool set_socket_timeout(SOCKET socket_handle, int timeout_milliseconds);
bool send_all(SOCKET socket_handle, const char* data, int data_length);
std::string describe_socket_error();
bool resolve_ipv4_endpoint(const std::string& host, std::uint16_t port, sockaddr_in& endpoint);

}  // namespace network_proxy
