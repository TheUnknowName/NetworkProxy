#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "protocol/protocol_detector.h"

namespace network_proxy {

struct ProtocolContext {
    ProtocolKind protocol_kind = ProtocolKind::Unknown;
    std::string direction;
    std::string host;
    std::string method;
    std::string path;
    std::uint16_t remote_port = 0;
    std::string process_name;
};

class ProtocolAdapter {
public:
    virtual ~ProtocolAdapter() = default;

    virtual bool can_handle(const ProtocolContext& context, std::string_view payload) const = 0;
    virtual bool apply_patch(std::string& payload, const ProtocolContext& context, PatchEngine& patch_engine, const AppConfig& config, Logger& logger) const = 0;
    virtual std::string adapter_name() const = 0;
};

class ProtocolManager {
public:
    ProtocolManager(const AppConfig& config, Logger& logger, PatchEngine& patch_engine);

    void register_default_adapters();
    bool patch_payload(std::string& payload, const ProtocolContext& context) const;

private:
    const AppConfig& config_;
    Logger& logger_;
    PatchEngine& patch_engine_;
    std::vector<std::unique_ptr<ProtocolAdapter>> adapters_;
};

}  // namespace network_proxy
