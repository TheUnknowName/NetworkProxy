#include "patch/patch_engine.h"

namespace network_proxy {

PatchEngine::PatchEngine(const AppConfig& config, Logger& logger)
    : config_(config), logger_(logger) {
}

void PatchEngine::apply_request_patch(HttpRequest& request) const {
    if (config_.add_proxy_header) {
        request.headers["X-Network-Proxy"] = "network_proxy";
    }

    if (config_.append_debug_suffix && !request.body.empty()) {
        request.body += "\n[patched-by-network-proxy-request]";
    }

    logger_.debug("request patch applied");
}

void PatchEngine::apply_response_patch(HttpResponse& response) const {
    if (config_.add_proxy_header) {
        response.headers["X-Network-Proxy"] = "network_proxy";
    }

    if (config_.append_debug_suffix && !response.body.empty()) {
        response.body += "\n[patched-by-network-proxy-response]";
    }

    logger_.debug("response patch applied");
}

}  // namespace network_proxy
