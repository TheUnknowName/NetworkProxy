#pragma once

#include <atomic>

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
    bool bind_functions();

    const AppConfig& config_;
    Logger& logger_;
    void* module_handle_ = nullptr;
    bool initialized_ = false;
    void* fwpm_engine_open_ = nullptr;
    void* fwpm_engine_close_ = nullptr;
};

}  // namespace network_proxy
