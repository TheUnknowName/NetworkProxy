#include "app/application.h"

#include <filesystem>
#include <iostream>
#include <string>

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "proxy/proxy_server.h"
#include "tls/certificate_manager.h"

namespace network_proxy {

namespace {

struct CommandLineOptions {
    std::filesystem::path config_path = "config/proxy.yaml";
    bool install_ca = false;
    bool uninstall_ca = false;
};

CommandLineOptions parse_options(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];

        if (argument == "--config" && index + 1 < argc) {
            options.config_path = argv[index + 1];
            ++index;
            continue;
        }

        if (argument == "--install-ca") {
            options.install_ca = true;
            continue;
        }

        if (argument == "--uninstall-ca") {
            options.uninstall_ca = true;
            continue;
        }
    }

    return options;
}

}  // namespace

int Application::run(int argc, char* argv[]) {
    const CommandLineOptions options = parse_options(argc, argv);
    const std::filesystem::path config_path = options.config_path;

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

    CertificateManager certificate_manager(logger);
    if (options.install_ca) {
        std::string command_error;
        if (!certificate_manager.install_root_ca(config.https_ca_cert_path, config.https_install_to_current_user, command_error)) {
            logger.error("install ca failed: " + command_error);
            return 1;
        }

        logger.info("install ca done");
        return 0;
    }

    if (options.uninstall_ca) {
        std::string command_error;
        if (!certificate_manager.uninstall_root_ca(config.https_ca_subject_name, config.https_install_to_current_user, command_error)) {
            logger.error("uninstall ca failed: " + command_error);
            return 1;
        }

        logger.info("uninstall ca done");
        return 0;
    }

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
