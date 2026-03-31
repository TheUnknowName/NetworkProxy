#include "capture/wfp_capture.h"

#include <chrono>
#include <thread>

#include <Windows.h>

namespace network_proxy {

WfpCapture::WfpCapture(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger) {
}

WfpCapture::~WfpCapture() {
    if (module_handle_ != nullptr) {
        FreeLibrary(static_cast<HMODULE>(module_handle_));
        module_handle_ = nullptr;
    }
}

bool WfpCapture::initialize() {
    if (!config_.capture_enabled || !config_.use_wfp) {
        logger_.info("wfp capture disabled by config");
        return false;
    }

    HMODULE module = LoadLibraryA("Fwpuclnt.dll");
    if (module == nullptr) {
        logger_.warn("Fwpuclnt.dll not found, wfp capture is not active");
        return false;
    }

    module_handle_ = module;
    if (!bind_functions()) {
        logger_.warn("wfp api resolve failed, fallback is required");
        return false;
    }

    initialized_ = true;
    logger_.info("wfp capture adapter initialized (scaffold mode)");
    return true;
}

void WfpCapture::run(std::atomic_bool& stop_requested) {
    if (!initialized_) {
        return;
    }

    logger_.warn("wfp capture run loop is scaffold mode; packet interception not fully implemented yet");
    while (!stop_requested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    logger_.info("wfp capture loop stopped");
}

bool WfpCapture::bind_functions() {
    if (module_handle_ == nullptr) {
        return false;
    }

    const auto module = static_cast<HMODULE>(module_handle_);
    fwpm_engine_open_ = reinterpret_cast<void*>(GetProcAddress(module, "FwpmEngineOpen0"));
    fwpm_engine_close_ = reinterpret_cast<void*>(GetProcAddress(module, "FwpmEngineClose0"));

    return fwpm_engine_open_ != nullptr && fwpm_engine_close_ != nullptr;
}

}  // namespace network_proxy
