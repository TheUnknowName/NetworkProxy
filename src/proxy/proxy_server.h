#pragma once

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"

namespace network_proxy {

class ProxyServer {
public:
    ProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine);

    bool run();

private:
    const AppConfig& config_;
    Logger& logger_;
    PatchEngine& patch_engine_;
};

}  // namespace network_proxy
