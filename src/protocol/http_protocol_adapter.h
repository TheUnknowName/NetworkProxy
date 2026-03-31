#pragma once

#include "protocol/protocol_manager.h"

namespace network_proxy {

class HttpProtocolAdapter final : public ProtocolAdapter {
public:
    bool can_handle(const ProtocolContext& context, std::string_view payload) const override;
    bool apply_patch(std::string& payload, const ProtocolContext& context, PatchEngine& patch_engine, const AppConfig& config, Logger& logger) const override;
    std::string adapter_name() const override;
};

}  // namespace network_proxy
