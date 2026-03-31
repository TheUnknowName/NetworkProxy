#include "proxy/proxy_server.h"

#include <string>

#include "protocol/http_types.h"

namespace network_proxy {

ProxyServer::ProxyServer(const AppConfig& config, Logger& logger, PatchEngine& patch_engine)
    : config_(config), logger_(logger), patch_engine_(patch_engine) {
}

bool ProxyServer::run() {
    logger_.info("proxy server bootstrap start");
    logger_.info("listen endpoint: " + config_.listen_host + ":" + std::to_string(config_.listen_port));

    HttpRequest request;
    request.method = "POST";
    request.target = "/api/demo";
    request.headers["Content-Type"] = "application/json";
    request.body = R"({"message":"hello"})";

    patch_engine_.apply_request_patch(request);
    logger_.info("patched request body: " + request.body);

    HttpResponse response;
    response.status_code = 200;
    response.headers["Content-Type"] = "application/json";
    response.body = R"({"status":"ok"})";

    patch_engine_.apply_response_patch(response);
    logger_.info("patched response body: " + response.body);

    if (config_.dry_run) {
        logger_.warn("dry_run enabled, network capture and forwarding are not started yet");
        return true;
    }

    logger_.warn("real proxy loop is not implemented yet");
    return true;
}

}  // namespace network_proxy
