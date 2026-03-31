#pragma once

#include <filesystem>
#include <string>

#include "logging/logger.h"

namespace network_proxy {

class CertificateManager {
public:
    explicit CertificateManager(Logger& logger);

    bool validate_ca_files(const std::filesystem::path& cert_path, const std::filesystem::path& key_path, std::string& error_message) const;
    bool install_root_ca(const std::filesystem::path& cert_path, bool install_to_current_user, std::string& error_message) const;
    bool uninstall_root_ca(const std::string& subject_name, bool install_to_current_user, std::string& error_message) const;
    bool generate_leaf_certificate(
        const std::string& host_name,
        const std::filesystem::path& ca_cert_path,
        const std::filesystem::path& ca_key_path,
        const std::filesystem::path& cache_dir,
        const std::string& openssl_bin_path,
        std::filesystem::path& leaf_cert_path,
        std::filesystem::path& leaf_key_path,
        std::string& error_message) const;

private:
    bool execute_command(const std::string& command, std::string& error_message) const;

    Logger& logger_;
};

}  // namespace network_proxy
