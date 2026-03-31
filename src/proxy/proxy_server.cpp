#include "proxy/proxy_server.h"

#include <chrono>
#include <thread>

#include <WinSock2.h>

#include "capture/win_divert_capture.h"
#include "capture/flow_table.h"
#include "capture/wfp_capture.h"
#include "protocol/protocol_manager.h"
#include "tls/https_mitm_proxy.h"
#include "transport/tcp_proxy_server.h"
#include "transport/udp_proxy_server.h"

namespace network_proxy {

ProxyServer::ProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine)
    : config_(config), logger_(logger), patch_engine_(patch_engine) {
}

bool ProxyServer::run() {
    logger_.info("proxy server bootstrap start");
    logger_.info("tcp enabled: " + std::string(config_.tcp_enabled ? "true" : "false"));
    logger_.info("udp enabled: " + std::string(config_.udp_enabled ? "true" : "false"));

    if (config_.dry_run) {
        logger_.warn("dry_run enabled, network capture and forwarding are not started yet");
        return true;
    }

    if (!initialize_winsock()) {
        return false;
    }

    std::atomic_bool stop_requested = false;
    FlowTable flow_table;
    enum class CaptureBackend {
        None,
        Wfp,
        WinDivert
    };
    CaptureBackend active_capture_backend = CaptureBackend::None;

    HttpsMitmProxy https_mitm_proxy(config_, logger_);
    if (!https_mitm_proxy.initialize()) {
        WSACleanup();
        return false;
    }

    WfpCapture wfp_capture(config_, logger_);
    WinDivertCapture win_divert_capture(config_, logger_, flow_table);
    if (config_.capture_enabled) {
        if (config_.use_wfp) {
            if (wfp_capture.initialize()) {
                active_capture_backend = CaptureBackend::Wfp;
            } else {
                logger_.warn("wfp capture init failed, fallback to windivert if enabled");
            }
        }

        if (active_capture_backend == CaptureBackend::None && config_.use_windivert) {
            if (!win_divert_capture.initialize()) {
                WSACleanup();
                return false;
            }
            active_capture_backend = CaptureBackend::WinDivert;
        }

        if (active_capture_backend == CaptureBackend::None) {
            logger_.warn("capture.enabled=true but no capture backend is active");
        }
    }

    ProtocolManager protocol_manager(config_, logger_, patch_engine_);
    protocol_manager.register_default_adapters();

    TcpProxyServer tcp_proxy_server(config_, logger_, patch_engine_, protocol_manager, https_mitm_proxy, flow_table);
    UdpProxyServer udp_proxy_server(config_, logger_, patch_engine_, protocol_manager, flow_table);

    std::jthread capture_thread;
    if (active_capture_backend == CaptureBackend::Wfp) {
        capture_thread = std::jthread([&]() {
            wfp_capture.run(stop_requested);
        });
    } else if (active_capture_backend == CaptureBackend::WinDivert) {
        capture_thread = std::jthread([&]() {
            win_divert_capture.run(stop_requested);
        });
    }

    std::jthread tcp_thread;
    if (config_.tcp_enabled) {
        tcp_thread = std::jthread([&]() {
            tcp_proxy_server.serve(stop_requested);
        });
    }

    std::jthread udp_thread;
    if (config_.udp_enabled) {
        udp_thread = std::jthread([&]() {
            udp_proxy_server.serve(stop_requested);
        });
    }

    if (config_.max_runtime_seconds == 0) {
        logger_.info("proxy server running, press Ctrl+C to stop");
        while (!stop_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        logger_.info("proxy server running for " + std::to_string(config_.max_runtime_seconds) + " seconds");
        std::this_thread::sleep_for(std::chrono::seconds(config_.max_runtime_seconds));
        stop_requested.store(true);
    }

    WSACleanup();
    return true;
}

bool ProxyServer::initialize_winsock() const {
    WSADATA wsa_data{};
    const int startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (startup_result != 0) {
        logger_.error("WSAStartup failed, error=" + std::to_string(startup_result));
        return false;
    }

    return true;
}

}  // namespace network_proxy

