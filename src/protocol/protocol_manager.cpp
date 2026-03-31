#include "protocol/protocol_manager.h"

#include "protocol/http_protocol_adapter.h"

namespace network_proxy {

ProtocolManager::ProtocolManager(const AppConfig& config, Logger& logger, PatchEngine& patch_engine)
    : config_(config), logger_(logger), patch_engine_(patch_engine) {
}

void ProtocolManager::register_default_adapters() {
    if (!config_.protocol_adapter_enabled) {
        logger_.warn("protocol adapter is disabled");
        return;
    }

    if (config_.http_adapter_enabled) {
        adapters_.push_back(std::make_unique<HttpProtocolAdapter>());
    }

    logger_.info("protocol adapters loaded: " + std::to_string(adapters_.size()));
}

bool ProtocolManager::patch_payload(std::string& payload, const ProtocolContext& context) const {
    if (!config_.protocol_adapter_enabled) {
        return false;
    }

    for (const auto& adapter : adapters_) {
        if (!adapter->can_handle(context, payload)) {
            continue;
        }

        if (adapter->apply_patch(payload, context, patch_engine_, config_, logger_)) {
            logger_.debug("adapter applied: " + adapter->adapter_name());
            return true;
        }
    }

    return false;
}

}  // namespace network_proxy
