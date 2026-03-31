#pragma once

#include <atomic>

#include <WinSock2.h>

#include "capture/flow_table.h"
#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "protocol/protocol_manager.h"

namespace network_proxy {

class HttpsMitmProxy;

class TcpProxyServer {
public:
    TcpProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine, ProtocolManager& protocol_manager, HttpsMitmProxy& https_mitm_proxy, FlowTable& flow_table);

    void serve(std::atomic_bool& stop_requested);

private:
    void handle_client(SOCKET client_socket, const sockaddr_storage& client_endpoint) const;

    const AppConfig& config_;
    Logger& logger_;
    PatchEngine& patch_engine_;
    ProtocolManager& protocol_manager_;
    HttpsMitmProxy& https_mitm_proxy_;
    FlowTable& flow_table_;
};

}  // namespace network_proxy
