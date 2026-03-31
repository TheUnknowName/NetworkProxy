#include "transport/udp_proxy_server.h"

#include <string>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "protocol/protocol_detector.h"
#include "transport/socket_utils.h"

namespace network_proxy {

namespace {

void close_socket_if_valid(SOCKET socket_handle) {
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
}

}  // namespace

UdpProxyServer::UdpProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine, ProtocolManager& protocol_manager)
    : config_(config), logger_(logger), patch_engine_(patch_engine), protocol_manager_(protocol_manager) {
}

void UdpProxyServer::serve(std::atomic_bool& stop_requested) {
    SOCKET listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET upstream_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket == INVALID_SOCKET || upstream_socket == INVALID_SOCKET) {
        logger_.error("udp socket create failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket);
        stop_requested.store(true);
        return;
    }

    set_socket_timeout(listen_socket, 500);
    set_socket_timeout(upstream_socket, 1000);

    sockaddr_in listen_endpoint{};
    if (!resolve_ipv4_endpoint(config_.udp_listen_host, config_.udp_listen_port, listen_endpoint)) {
        logger_.error("udp listen host parse failed: " + config_.udp_listen_host);
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket);
        stop_requested.store(true);
        return;
    }

    if (bind(listen_socket, reinterpret_cast<const sockaddr*>(&listen_endpoint), sizeof(listen_endpoint)) == SOCKET_ERROR) {
        logger_.error("udp bind failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket);
        stop_requested.store(true);
        return;
    }

    sockaddr_in upstream_endpoint{};
    if (!resolve_ipv4_endpoint(config_.udp_upstream_host, config_.udp_upstream_port, upstream_endpoint)) {
        logger_.error("udp upstream host parse failed: " + config_.udp_upstream_host);
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket);
        stop_requested.store(true);
        return;
    }

    logger_.info("udp proxy listening on " + config_.udp_listen_host + ":" + std::to_string(config_.udp_listen_port));

    char buffer[65535];
    char upstream_buffer[65535];
    while (!stop_requested.load()) {
        sockaddr_in client_endpoint{};
        int client_endpoint_length = sizeof(client_endpoint);
        const int received = recvfrom(listen_socket, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&client_endpoint), &client_endpoint_length);
        if (received == SOCKET_ERROR) {
            const int last_error = WSAGetLastError();
            if (last_error == WSAETIMEDOUT || last_error == WSAEWOULDBLOCK) {
                continue;
            }

            logger_.warn("udp recvfrom failed, error=" + std::to_string(last_error));
            continue;
        }

        std::string outbound_payload(buffer, buffer + received);
        ProtocolContext outbound_context;
        outbound_context.direction = "outbound";
        outbound_context.protocol_kind = detect_protocol_kind(outbound_payload);
        const bool outbound_structured = protocol_manager_.patch_payload(outbound_payload, outbound_context);
        if (!outbound_structured) {
            patch_engine_.apply_transport_patch(outbound_payload, "udp", "outbound");
        }

        const int upstream_sent = sendto(
            upstream_socket,
            outbound_payload.data(),
            static_cast<int>(outbound_payload.size()),
            0,
            reinterpret_cast<const sockaddr*>(&upstream_endpoint),
            sizeof(upstream_endpoint));

        if (upstream_sent == SOCKET_ERROR) {
            logger_.warn("udp sendto upstream failed, error=" + describe_socket_error());
            continue;
        }

        sockaddr_in upstream_sender{};
        int upstream_sender_length = sizeof(upstream_sender);
        const int upstream_received = recvfrom(
            upstream_socket,
            upstream_buffer,
            sizeof(upstream_buffer),
            0,
            reinterpret_cast<sockaddr*>(&upstream_sender),
            &upstream_sender_length);

        if (upstream_received == SOCKET_ERROR) {
            const int last_error = WSAGetLastError();
            if (last_error != WSAETIMEDOUT && last_error != WSAEWOULDBLOCK) {
                logger_.warn("udp recvfrom upstream failed, error=" + std::to_string(last_error));
            }
            continue;
        }

        std::string inbound_payload(upstream_buffer, upstream_buffer + upstream_received);
        ProtocolContext inbound_context;
        inbound_context.direction = "inbound";
        inbound_context.protocol_kind = detect_protocol_kind(inbound_payload);
        const bool inbound_structured = protocol_manager_.patch_payload(inbound_payload, inbound_context);
        if (!inbound_structured) {
            patch_engine_.apply_transport_patch(inbound_payload, "udp", "inbound");
        }

        const int client_sent = sendto(
            listen_socket,
            inbound_payload.data(),
            static_cast<int>(inbound_payload.size()),
            0,
            reinterpret_cast<const sockaddr*>(&client_endpoint),
            client_endpoint_length);

        if (client_sent == SOCKET_ERROR) {
            logger_.warn("udp sendto client failed, error=" + describe_socket_error());
        }
    }

    close_socket_if_valid(listen_socket);
    close_socket_if_valid(upstream_socket);
}

}  // namespace network_proxy