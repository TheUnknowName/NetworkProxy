#include "capture/wfp_capture.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

#include <WinSock2.h>
#include <Windows.h>
#include <fwpmu.h>

#include <WS2tcpip.h>

namespace network_proxy {

namespace {

std::string endpoint_to_text_v4(std::uint32_t address_v4, std::uint16_t port) {
    in_addr ipv4{};
    ipv4.S_un.S_addr = address_v4;

    char buffer[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &ipv4, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) {
        return "";
    }

    return std::string(buffer) + ":" + std::to_string(port);
}

std::string endpoint_to_text_v6(const FWP_BYTE_ARRAY16* address, std::uint16_t port) {
    if (address == nullptr) {
        return "";
    }

    char buffer[INET6_ADDRSTRLEN]{};
    in6_addr ipv6{};
    std::memcpy(&ipv6, address->byteArray16, sizeof(ipv6));
    if (InetNtopA(AF_INET6, &ipv6, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) {
        return "";
    }

    return std::string(buffer) + ":" + std::to_string(port);
}

}  // namespace

WfpCapture::WfpCapture(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger) {
}

WfpCapture::~WfpCapture() {
    if (subscription_handle_ != nullptr && engine_handle_ != nullptr) {
        FwpmNetEventUnsubscribe0(static_cast<HANDLE>(engine_handle_), static_cast<HANDLE>(subscription_handle_));
        subscription_handle_ = nullptr;
    }

    if (engine_handle_ != nullptr) {
        FwpmEngineClose0(static_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
    }
}

bool WfpCapture::initialize() {
    if (!config_.capture_enabled || !config_.use_wfp) {
        logger_.info("wfp capture disabled by config");
        return false;
    }

    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"NetworkProxy WFP Session");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    const DWORD open_result = FwpmEngineOpen0(
        nullptr,
        RPC_C_AUTHN_WINNT,
        nullptr,
        &session,
        reinterpret_cast<HANDLE*>(&engine_handle_));
    if (open_result != ERROR_SUCCESS) {
        logger_.warn("wfp engine open failed, code=" + std::to_string(open_result));
        return false;
    }

    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
    subscription.enumTemplate = nullptr;

    const DWORD subscribe_result = FwpmNetEventSubscribe0(
        static_cast<HANDLE>(engine_handle_),
        &subscription,
        &WfpCapture::on_net_event,
        this,
        reinterpret_cast<HANDLE*>(&subscription_handle_));
    if (subscribe_result != ERROR_SUCCESS) {
        logger_.warn("wfp net event subscribe failed, code=" + std::to_string(subscribe_result));
        FwpmEngineClose0(static_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
        return false;
    }

    initialized_ = true;
    logger_.info("wfp capture adapter initialized with net-event subscription");
    return true;
}

void WfpCapture::run(std::atomic_bool& stop_requested) {
    if (!initialized_) {
        return;
    }

    logger_.info("wfp capture loop started");
    while (!stop_requested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    logger_.info("wfp capture loop stopped");
}

void __stdcall WfpCapture::on_net_event(void* context, const FWPM_NET_EVENT1* net_event) {
    if (context == nullptr || net_event == nullptr) {
        return;
    }

    auto* self = static_cast<WfpCapture*>(context);
    const auto* event = net_event;
    if (event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || event->classifyDrop == nullptr) {
        return;
    }

    const auto& header = event->header;
    const std::uint16_t local_port = header.localPort;
    const std::uint16_t remote_port = header.remotePort;

    std::string local_text;
    std::string remote_text;
    if (header.ipVersion == FWP_IP_VERSION_V4) {
        local_text = endpoint_to_text_v4(header.localAddrV4, local_port);
        remote_text = endpoint_to_text_v4(header.remoteAddrV4, remote_port);
    } else {
        local_text = endpoint_to_text_v6(&header.localAddrV6, local_port);
        remote_text = endpoint_to_text_v6(&header.remoteAddrV6, remote_port);
    }

    self->logger_.debug("wfp classify_drop protocol=" + std::to_string(header.ipProtocol) + " local=" + local_text + " remote=" + remote_text);
}

}  // namespace network_proxy
