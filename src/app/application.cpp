#include "app/application.h"

#include <filesystem>
#include <iostream>
#include <string>

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "proxy/proxy_server.h"

namespace network_proxy {

namespace {

std::filesystem::path parse_config_path(int argc, char* argv[]) {
    std::filesystem::path config_path = "config/proxy.yaml";

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];

        if (argument == "--config" && index + 1 < argc) {
            config_path = argv[index + 1];
            ++index;
        }
    }

    return config_path;
}

}  // namespace

int Application::run(int argc, char* argv[]) {
    const std::filesystem::path config_path = parse_config_path(argc, argv);

    AppConfig config;
    std::string error_message;
    if (!config.load_from_file(config_path, error_message)) {
        std::cerr << "failed to load config: " << error_message << '\n';
        return 1;
    }

    Logger logger;
    logger.set_level(parse_log_level(config.log_level));
    logger.info("application starting");
    logger.info("config path: " + config_path.string());

    PatchEngine patch_engine(config, logger);
    ProxyServer proxy_server(config, logger, patch_engine);

    if (!proxy_server.run()) {
        logger.error("proxy server run failed");
        return 1;
    }

    logger.info("application stopped");
    return 0;
}

}  // namespace network_proxy
