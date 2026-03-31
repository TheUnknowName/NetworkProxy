#pragma once

#include <atomic>
#include <memory>

#include <WinSock2.h>
#include <Windows.h>
#include <fwpmtypes.h>

#include "capture/wfp_redirect_controller.h"
#include "config/app_config.h"
#include "logging/logger.h"

namespace network_proxy {

class WfpCapture {
public:
    WfpCapture(const AppConfig& config, Logger& logger);
    ~WfpCapture();

    bool initialize();
    void run(std::atomic_bool& stop_requested);
    bool fallback_requested() const;
    std::string fallback_reason() const;

private:
    static void __stdcall on_net_event(void* context, const FWPM_NET_EVENT1* net_event);

    const AppConfig& config_;
    Logger& logger_;
    bool initialized_ = false;
    void* engine_handle_ = nullptr;
    void* subscription_handle_ = nullptr;
    std::unique_ptr<WfpRedirectController> redirect_controller_;
    std::atomic_bool fallback_requested_{false};
    std::string fallback_reason_;
};

}  // namespace network_proxy
