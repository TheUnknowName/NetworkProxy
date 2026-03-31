#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include <WinSock2.h>

#include "config/app_config.h"
#include "logging/logger.h"

namespace network_proxy {

class PatchEngine;
class ProtocolManager;

class HttpsMitmProxy {
public:
    HttpsMitmProxy(const AppConfig& config, Logger& logger);

    bool initialize();
    bool try_extract_sni_from_client_hello(std::string_view client_hello, std::string& server_name) const;
    bool ensure_leaf_certificate_for_host(const std::string& host_name, std::filesystem::path& cert_path, std::filesystem::path& key_path) const;
    bool patch_https_plaintext_http(std::string& plaintext_payload, const std::string& direction, ProtocolManager& protocol_manager, PatchEngine& patch_engine) const;
    bool run_tls_mitm_session(SOCKET client_socket, const std::string& upstream_host, std::uint16_t upstream_port, ProtocolManager& protocol_manager, PatchEngine& patch_engine) const;

private:
    static std::uint16_t allocate_local_port();
    static SOCKET connect_local_port(std::uint16_t port);

    const AppConfig& config_;
    Logger& logger_;
};

}  // namespace network_proxy
