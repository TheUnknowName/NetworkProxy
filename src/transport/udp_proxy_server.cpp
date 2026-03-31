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

UdpProxyServer::UdpProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine, ProtocolManager& protocol_manager, FlowTable& flow_table)
    : config_(config), logger_(logger), patch_engine_(patch_engine), protocol_manager_(protocol_manager), flow_table_(flow_table) {
}

void UdpProxyServer::serve(std::atomic_bool& stop_requested) {
    sockaddr_storage listen_endpoint{};
    int listen_endpoint_length = 0;
    if (!resolve_endpoint(config_.udp_listen_host, config_.udp_listen_port, listen_endpoint, listen_endpoint_length, SOCK_DGRAM)) {
        logger_.error("udp listen host parse failed: " + config_.udp_listen_host);
        stop_requested.store(true);
        return;
    }

    SOCKET listen_socket = socket(listen_endpoint.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET upstream_socket_v4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET upstream_socket_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket == INVALID_SOCKET || upstream_socket_v4 == INVALID_SOCKET) {
        logger_.error("udp socket create failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket_v4);
        close_socket_if_valid(upstream_socket_v6);
        stop_requested.store(true);
        return;
    }

    if (upstream_socket_v6 != INVALID_SOCKET) {
        const DWORD upstream_v6_only = 1;
        setsockopt(upstream_socket_v6, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&upstream_v6_only), sizeof(upstream_v6_only));
    }

    if (listen_endpoint.ss_family == AF_INET6) {
        const DWORD listen_v6_only = 0;
        setsockopt(listen_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&listen_v6_only), sizeof(listen_v6_only));
    }

    set_socket_timeout(listen_socket, 500);
    set_socket_timeout(upstream_socket_v4, 1000);
    if (upstream_socket_v6 != INVALID_SOCKET) {
        set_socket_timeout(upstream_socket_v6, 1000);
    }

    if (bind(listen_socket, reinterpret_cast<const sockaddr*>(&listen_endpoint), listen_endpoint_length) == SOCKET_ERROR) {
        logger_.error("udp bind failed, error=" + describe_socket_error());
        close_socket_if_valid(listen_socket);
        close_socket_if_valid(upstream_socket_v4);
        close_socket_if_valid(upstream_socket_v6);
        stop_requested.store(true);
        return;
    }

    logger_.info("udp proxy listening on " + config_.udp_listen_host + ":" + std::to_string(config_.udp_listen_port));

    char buffer[65535];
    char upstream_buffer[65535];
    while (!stop_requested.load()) {
        sockaddr_storage client_endpoint{};
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

        std::string upstream_host = config_.udp_upstream_host;
        std::uint16_t upstream_port = config_.udp_upstream_port;
        const std::string client_source_ip = endpoint_ip_to_string(reinterpret_cast<const sockaddr*>(&client_endpoint));
        const std::uint16_t client_source_port = endpoint_port(reinterpret_cast<const sockaddr*>(&client_endpoint));
        const auto mapped_target = flow_table_.try_get_upstream(17, client_source_ip, client_source_port);
        if (mapped_target.has_value()) {
            upstream_host = mapped_target->first;
            upstream_port = mapped_target->second;
        }

        sockaddr_storage upstream_endpoint{};
        int upstream_endpoint_length = 0;
        if (!resolve_endpoint(upstream_host, upstream_port, upstream_endpoint, upstream_endpoint_length, SOCK_DGRAM)) {
            logger_.warn("udp upstream host parse failed: " + upstream_host);
            continue;
        }

        std::string outbound_payload(buffer, buffer + received);
        ProtocolContext outbound_context;
        outbound_context.direction = "outbound";
        outbound_context.protocol_kind = detect_protocol_kind(outbound_payload);
        outbound_context.host = upstream_host;
        outbound_context.remote_port = upstream_port;
        const bool outbound_structured = protocol_manager_.patch_payload(outbound_payload, outbound_context);
        if (!outbound_structured) {
            RuleMatchContext match_context;
            match_context.protocol = "udp";
            match_context.direction = "outbound";
            match_context.host = upstream_host;
            match_context.remote_port = upstream_port;
            patch_engine_.apply_transport_patch(outbound_payload, "udp", "outbound", &match_context);
        }

        const SOCKET active_upstream_socket = (upstream_endpoint.ss_family == AF_INET6) ? upstream_socket_v6 : upstream_socket_v4;
        if (active_upstream_socket == INVALID_SOCKET) {
            logger_.warn("udp sendto upstream failed, error=no ipv6 upstream socket");
            continue;
        }

        const int upstream_sent = sendto(
            active_upstream_socket,
            outbound_payload.data(),
            static_cast<int>(outbound_payload.size()),
            0,
            reinterpret_cast<const sockaddr*>(&upstream_endpoint),
            upstream_endpoint_length);

        if (upstream_sent == SOCKET_ERROR) {
            logger_.warn("udp sendto upstream failed, error=" + describe_socket_error());
            continue;
        }

        sockaddr_storage upstream_sender{};
        int upstream_sender_length = sizeof(upstream_sender);
        const int upstream_received = recvfrom(
            active_upstream_socket,
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
        inbound_context.host = upstream_host;
        inbound_context.remote_port = upstream_port;
        const bool inbound_structured = protocol_manager_.patch_payload(inbound_payload, inbound_context);
        if (!inbound_structured) {
            RuleMatchContext match_context;
            match_context.protocol = "udp";
            match_context.direction = "inbound";
            match_context.host = upstream_host;
            match_context.remote_port = upstream_port;
            patch_engine_.apply_transport_patch(inbound_payload, "udp", "inbound", &match_context);
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
    close_socket_if_valid(upstream_socket_v4);
    close_socket_if_valid(upstream_socket_v6);
}

}  // namespace network_proxy