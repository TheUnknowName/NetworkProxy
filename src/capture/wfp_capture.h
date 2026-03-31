#pragma once

#include <atomic>

#include <WinSock2.h>
#include <Windows.h>
#include <fwpmtypes.h>

#include "config/app_config.h"
#include "logging/logger.h"

namespace network_proxy {

class WfpCapture {
public:
    WfpCapture(const AppConfig& config, Logger& logger);
    ~WfpCapture();

    bool initialize();
    void run(std::atomic_bool& stop_requested);

private:
    static void __stdcall on_net_event(void* context, const FWPM_NET_EVENT1* net_event);

    const AppConfig& config_;
    Logger& logger_;
    bool initialized_ = false;
    void* engine_handle_ = nullptr;
    void* subscription_handle_ = nullptr;
};

}  // namespace network_proxy
