#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

#include "config/app_config.h"
#include "logging/logger.h"

namespace network_proxy {

struct WfpRedirectPolicy {
    std::string filter_expression;
    std::string callout_channel;
    std::string tcp_redirect_host;
    std::uint16_t tcp_redirect_port = 0;
    std::string udp_redirect_host;
    std::uint16_t udp_redirect_port = 0;
    bool enable_tcp = true;
    bool enable_udp = true;
};

class IWfpCalloutBridge {
public:
    virtual ~IWfpCalloutBridge() = default;

    virtual bool connect(const std::string& channel, std::string& error_message) = 0;
    virtual bool apply_policy(const WfpRedirectPolicy& policy, std::string& error_message) = 0;
    virtual bool clear_policy(std::string& error_message) = 0;
    virtual bool check_health(std::string& error_message) const = 0;
};

class WfpRedirectController {
public:
    WfpRedirectController(const AppConfig& config, Logger& logger);
    ~WfpRedirectController();

    bool initialize();
    void tick_health();
    void shutdown();

    bool fallback_requested() const;
    std::string fallback_reason() const;

private:
    bool apply_default_policy();
    void request_fallback(const std::string& reason);

    const AppConfig& config_;
    Logger& logger_;
    std::unique_ptr<IWfpCalloutBridge> bridge_;

    std::atomic_bool initialized_{false};
    std::atomic_bool policy_applied_{false};
    std::atomic_bool fallback_requested_{false};

    mutable std::mutex fallback_mutex_;
    std::string fallback_reason_;
};

}  // namespace network_proxy
