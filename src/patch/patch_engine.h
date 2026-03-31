#pragma once

#include "config/app_config.h"
#include "logging/logger.h"
#include "protocol/http_types.h"

namespace network_proxy {

class PatchEngine {
public:
    PatchEngine(const AppConfig& config, Logger& logger);

    void apply_request_patch(HttpRequest& request) const;
    void apply_response_patch(HttpResponse& response) const;

private:
    const AppConfig& config_;
    Logger& logger_;
};

}  // namespace network_proxy
