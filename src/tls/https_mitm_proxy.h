#pragma once

#include <filesystem>
#include <string>
#include <string_view>

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

private:
    const AppConfig& config_;
    Logger& logger_;
};

}  // namespace network_proxy
