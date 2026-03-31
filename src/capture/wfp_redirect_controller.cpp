#include "capture/wfp_redirect_controller.h"

#include <utility>

namespace network_proxy {

namespace {

class LocalCalloutBridge final : public IWfpCalloutBridge {
public:
    bool connect(const std::string& channel, std::string& error_message) override {
        if (channel.empty()) {
            error_message = "callout channel is empty";
            return false;
        }

        channel_ = channel;
        connected_ = true;
        return true;
    }

    bool apply_policy(const WfpRedirectPolicy& policy, std::string& error_message) override {
        if (!connected_) {
            error_message = "callout bridge is not connected";
            return false;
        }

        if (policy.filter_expression.empty()) {
            error_message = "redirect policy filter is empty";
            return false;
        }

        if (!policy.enable_tcp && !policy.enable_udp) {
            error_message = "redirect policy disables both tcp and udp";
            return false;
        }

        cached_policy_ = policy;
        policy_applied_ = true;
        return true;
    }

    bool clear_policy(std::string& error_message) override {
        if (!connected_) {
            error_message = "callout bridge is not connected";
            return false;
        }

        policy_applied_ = false;
        cached_policy_ = WfpRedirectPolicy{};
        return true;
    }

    bool check_health(std::string& error_message) const override {
        if (!connected_) {
            error_message = "callout bridge disconnected";
            return false;
        }

        if (!policy_applied_) {
            error_message = "callout policy is not active";
            return false;
        }

        return true;
    }

private:
    bool connected_ = false;
    bool policy_applied_ = false;
    std::string channel_;
    WfpRedirectPolicy cached_policy_{};
};

}  // namespace

WfpRedirectController::WfpRedirectController(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger), bridge_(std::make_unique<LocalCalloutBridge>()) {
}

WfpRedirectController::~WfpRedirectController() {
    shutdown();
}

bool WfpRedirectController::initialize() {
    if (!config_.wfp_redirect_enabled) {
        logger_.info("wfp redirect controller disabled by config");
        return true;
    }

    std::string error_message;
    if (!bridge_->connect(config_.wfp_callout_channel, error_message)) {
        logger_.warn("wfp redirect callout connect failed: " + error_message);
        request_fallback("callout connect failed: " + error_message);
        return false;
    }

    if (!apply_default_policy()) {
        return false;
    }

    initialized_.store(true);
    logger_.info("wfp redirect controller initialized");
    return true;
}

void WfpRedirectController::tick_health() {
    if (!initialized_.load() || fallback_requested_.load() || !config_.wfp_redirect_enabled) {
        return;
    }

    std::string error_message;
    if (!bridge_->check_health(error_message)) {
        logger_.warn("wfp redirect health check failed: " + error_message);
        request_fallback("redirect health check failed: " + error_message);
    }
}

void WfpRedirectController::shutdown() {
    if (!initialized_.exchange(false)) {
        return;
    }

    std::string error_message;
    if (!bridge_->clear_policy(error_message)) {
        logger_.warn("wfp redirect clear policy failed: " + error_message);
    }

    policy_applied_.store(false);
}

bool WfpRedirectController::fallback_requested() const {
    return fallback_requested_.load();
}

std::string WfpRedirectController::fallback_reason() const {
    std::lock_guard<std::mutex> lock(fallback_mutex_);
    return fallback_reason_;
}

bool WfpRedirectController::apply_default_policy() {
    WfpRedirectPolicy policy{};
    policy.filter_expression = config_.wfp_redirect_filter;
    policy.callout_channel = config_.wfp_callout_channel;
    policy.tcp_redirect_host = config_.tcp_listen_host;
    policy.tcp_redirect_port = config_.tcp_listen_port;
    policy.udp_redirect_host = config_.udp_listen_host;
    policy.udp_redirect_port = config_.udp_listen_port;
    policy.enable_tcp = config_.tcp_enabled;
    policy.enable_udp = config_.udp_enabled;

    std::string error_message;
    if (!bridge_->apply_policy(policy, error_message)) {
        logger_.warn("wfp redirect apply policy failed: " + error_message);
        request_fallback("apply policy failed: " + error_message);
        return false;
    }

    policy_applied_.store(true);
    logger_.info("wfp redirect policy applied");
    return true;
}

void WfpRedirectController::request_fallback(const std::string& reason) {
    fallback_requested_.store(true);
    {
        std::lock_guard<std::mutex> lock(fallback_mutex_);
        fallback_reason_ = reason;
    }
}

}  // namespace network_proxy
