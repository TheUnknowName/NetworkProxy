#pragma once

#include <atomic>

#include "capture/flow_table.h"
#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "protocol/protocol_manager.h"

namespace network_proxy {

class UdpProxyServer {
public:
    UdpProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine, ProtocolManager& protocol_manager, FlowTable& flow_table);

    void serve(std::atomic_bool& stop_requested);

private:
    const AppConfig& config_;
    Logger& logger_;
    PatchEngine& patch_engine_;
    ProtocolManager& protocol_manager_;
    FlowTable& flow_table_;
};

}  // namespace network_proxy
