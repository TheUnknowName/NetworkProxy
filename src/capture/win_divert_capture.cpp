#include "capture/win_divert_capture.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <thread>

#include <WinSock2.h>
#include <Windows.h>

namespace network_proxy {

namespace {

#pragma pack(push, 1)
struct Ipv4Header {
    std::uint8_t version_ihl;
    std::uint8_t dscp_ecn;
    std::uint16_t total_length;
    std::uint16_t identification;
    std::uint16_t flags_fragment;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t header_checksum;
    std::uint32_t source_ip;
    std::uint32_t destination_ip;
};

struct TcpHeader {
    std::uint16_t source_port;
    std::uint16_t destination_port;
};

struct UdpHeader {
    std::uint16_t source_port;
    std::uint16_t destination_port;
};
#pragma pack(pop)

constexpr unsigned short k_windivert_layer_network = 0;
constexpr unsigned char k_protocol_tcp = 6;
constexpr unsigned char k_protocol_udp = 17;
constexpr std::uint32_t k_loopback_ipv4_network_order = 0x0100007F;  // 127.0.0.1

}  // namespace

WinDivertCapture::WinDivertCapture(const AppConfig& config, Logger& logger, FlowTable& flow_table)
    : config_(config), logger_(logger), flow_table_(flow_table) {
}

WinDivertCapture::~WinDivertCapture() {
    if (divert_handle_ != nullptr && windivert_close_ != nullptr) {
        windivert_close_(divert_handle_);
        divert_handle_ = nullptr;
    }

    if (module_handle_ != nullptr) {
        FreeLibrary(static_cast<HMODULE>(module_handle_));
        module_handle_ = nullptr;
    }
}

bool WinDivertCapture::initialize() {
    if (!config_.capture_enabled || !config_.use_windivert) {
        logger_.info("windivert capture disabled by config");
        return true;
    }

    HMODULE module = LoadLibraryA("WinDivert.dll");
    if (module == nullptr) {
        logger_.warn("WinDivert.dll not found, system capture is not active");
        return false;
    }

    module_handle_ = module;
    if (!bind_functions()) {
        logger_.error("windivert api resolve failed");
        return false;
    }

    divert_handle_ = windivert_open_(config_.windivert_filter.c_str(), k_windivert_layer_network, 0, 0);
    if (divert_handle_ == nullptr) {
        logger_.error("windivert open failed, filter=" + config_.windivert_filter);
        return false;
    }

    logger_.info("windivert initialized with filter: " + config_.windivert_filter);
    return true;
}

void WinDivertCapture::run(std::atomic_bool& stop_requested) {
    if (!config_.capture_enabled || !config_.use_windivert || divert_handle_ == nullptr) {
        return;
    }

    constexpr unsigned int k_max_packet_size = 0xFFFF;
    unsigned char packet_buffer[k_max_packet_size]{};
    WindivertAddress address{};

    unsigned long long packet_count = 0;
    unsigned long long redirected_count = 0;
    logger_.info("windivert capture loop started");

    while (!stop_requested.load()) {
        unsigned int receive_length = 0;
        const int receive_ok = windivert_recv_(
            divert_handle_,
            packet_buffer,
            k_max_packet_size,
            &receive_length,
            &address);

        if (receive_ok == 0 || receive_length == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }

        bool rewritten = rewrite_packet_to_local_proxy(packet_buffer, receive_length);
        if (rewritten) {
            ++redirected_count;
            if (windivert_calc_checksums_ != nullptr) {
                windivert_calc_checksums_(packet_buffer, receive_length, &address, 0);
            }
        }

        unsigned int send_length = 0;
        const int send_ok = windivert_send_(
            divert_handle_,
            packet_buffer,
            receive_length,
            &send_length,
            &address);

        if (send_ok == 0) {
            logger_.warn("windivert send failed");
            continue;
        }

        ++packet_count;
        if ((packet_count % 2000ULL) == 0ULL) {
            logger_.info("windivert relayed packets=" + std::to_string(packet_count) + ", redirected=" + std::to_string(redirected_count));
        }
    }

    logger_.info("windivert capture loop stopped");
}

bool WinDivertCapture::bind_functions() {
    if (module_handle_ == nullptr) {
        return false;
    }

    const auto module = static_cast<HMODULE>(module_handle_);
    windivert_open_ = reinterpret_cast<windivert_open_fn>(GetProcAddress(module, "WinDivertOpen"));
    windivert_close_ = reinterpret_cast<windivert_close_fn>(GetProcAddress(module, "WinDivertClose"));
    windivert_recv_ = reinterpret_cast<windivert_recv_fn>(GetProcAddress(module, "WinDivertRecv"));
    windivert_send_ = reinterpret_cast<windivert_send_fn>(GetProcAddress(module, "WinDivertSend"));
    windivert_calc_checksums_ = reinterpret_cast<windivert_calc_checksums_fn>(GetProcAddress(module, "WinDivertHelperCalcChecksums"));

    return windivert_open_ != nullptr && windivert_close_ != nullptr && windivert_recv_ != nullptr && windivert_send_ != nullptr;
}

bool WinDivertCapture::rewrite_packet_to_local_proxy(unsigned char* packet_data, unsigned int packet_length) const {
    if (packet_data == nullptr || packet_length < sizeof(Ipv4Header)) {
        return false;
    }

    auto* ip_header = reinterpret_cast<Ipv4Header*>(packet_data);
    const std::uint8_t version = static_cast<std::uint8_t>((ip_header->version_ihl >> 4U) & 0x0F);
    const std::size_t ihl_bytes = static_cast<std::size_t>(ip_header->version_ihl & 0x0F) * 4U;

    if (version != 4 || ihl_bytes < sizeof(Ipv4Header) || packet_length < ihl_bytes) {
        return false;
    }

    if (ip_header->destination_ip == htonl(k_loopback_ipv4_network_order)) {
        return false;
    }

    if (ip_header->protocol == k_protocol_tcp) {
        if (!config_.tcp_enabled || packet_length < ihl_bytes + sizeof(TcpHeader)) {
            return false;
        }

        auto* tcp_header = reinterpret_cast<TcpHeader*>(packet_data + ihl_bytes);
        const std::uint32_t original_destination_ip = ip_header->destination_ip;
        const std::uint16_t destination_port = ntohs(tcp_header->destination_port);
        const std::uint16_t source_port = ntohs(tcp_header->source_port);
        if (destination_port == config_.tcp_listen_port) {
            return false;
        }

        flow_table_.remember_mapping(k_protocol_tcp, ip_header->source_ip, source_port, original_destination_ip, destination_port);

        tcp_header->destination_port = htons(config_.tcp_listen_port);
        ip_header->destination_ip = htonl(k_loopback_ipv4_network_order);
        return true;
    }

    if (ip_header->protocol == k_protocol_udp) {
        if (!config_.udp_enabled || packet_length < ihl_bytes + sizeof(UdpHeader)) {
            return false;
        }

        auto* udp_header = reinterpret_cast<UdpHeader*>(packet_data + ihl_bytes);
        const std::uint32_t original_destination_ip = ip_header->destination_ip;
        const std::uint16_t destination_port = ntohs(udp_header->destination_port);
        const std::uint16_t source_port = ntohs(udp_header->source_port);
        if (destination_port == config_.udp_listen_port) {
            return false;
        }

        flow_table_.remember_mapping(k_protocol_udp, ip_header->source_ip, source_port, original_destination_ip, destination_port);

        udp_header->destination_port = htons(config_.udp_listen_port);
        ip_header->destination_ip = htonl(k_loopback_ipv4_network_order);
        return true;
    }

    return false;
}

}  // namespace network_proxy
