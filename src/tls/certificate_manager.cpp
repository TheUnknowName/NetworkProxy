#include "tls/certificate_manager.h"

#include <cstdlib>
#include <fstream>

namespace network_proxy {

CertificateManager::CertificateManager(Logger& logger)
    : logger_(logger) {
}

bool CertificateManager::validate_ca_files(const std::filesystem::path& cert_path, const std::filesystem::path& key_path, std::string& error_message) const {
    if (!std::filesystem::exists(cert_path)) {
        error_message = "ca cert file not found: " + cert_path.string();
        return false;
    }

    if (!std::filesystem::exists(key_path)) {
        error_message = "ca key file not found: " + key_path.string();
        return false;
    }

    return true;
}

bool CertificateManager::install_root_ca(const std::filesystem::path& cert_path, bool install_to_current_user, std::string& error_message) const {
    if (!std::filesystem::exists(cert_path)) {
        error_message = "ca cert file not found: " + cert_path.string();
        return false;
    }

    const std::string scope_flag = install_to_current_user ? "-user " : "";
    const std::string command = "certutil " + scope_flag + "-f -addstore Root \"" + cert_path.string() + "\"";
    return execute_command(command, error_message);
}

bool CertificateManager::uninstall_root_ca(const std::string& subject_name, bool install_to_current_user, std::string& error_message) const {
    if (subject_name.empty()) {
        error_message = "subject_name is empty";
        return false;
    }

    const std::string scope_flag = install_to_current_user ? "-user " : "";
    const std::string command = "certutil " + scope_flag + "-delstore Root \"" + subject_name + "\"";
    return execute_command(command, error_message);
}

bool CertificateManager::execute_command(const std::string& command, std::string& error_message) const {
    logger_.info("execute command: " + command);
    const int result = std::system(command.c_str());
    if (result != 0) {
        error_message = "command failed, exit code=" + std::to_string(result);
        return false;
    }

    return true;
}

bool CertificateManager::generate_leaf_certificate(
    const std::string& host_name,
    const std::filesystem::path& ca_cert_path,
    const std::filesystem::path& ca_key_path,
    const std::filesystem::path& cache_dir,
    const std::string& openssl_bin_path,
    std::filesystem::path& leaf_cert_path,
    std::filesystem::path& leaf_key_path,
    std::string& error_message) const {
    if (host_name.empty()) {
        error_message = "host_name is empty";
        return false;
    }

    if (!validate_ca_files(ca_cert_path, ca_key_path, error_message)) {
        return false;
    }

    std::error_code create_directory_error;
    std::filesystem::create_directories(cache_dir, create_directory_error);
    if (create_directory_error) {
        error_message = "failed to create cache directory: " + cache_dir.string();
        return false;
    }

    std::string sanitized_host = host_name;
    for (char& character : sanitized_host) {
        if (character == ':' || character == '*' || character == '?' || character == '"' || character == '<' || character == '>' || character == '|') {
            character = '_';
        }
    }

    const std::filesystem::path csr_path = cache_dir / (sanitized_host + ".csr");
    leaf_cert_path = cache_dir / (sanitized_host + ".crt");
    leaf_key_path = cache_dir / (sanitized_host + ".key");
    const std::filesystem::path ext_path = cache_dir / (sanitized_host + ".ext");

    if (std::filesystem::exists(leaf_cert_path) && std::filesystem::exists(leaf_key_path)) {
        return true;
    }

    {
        std::ofstream ext_file(ext_path, std::ios::trunc);
        if (!ext_file.is_open()) {
            error_message = "cannot create openssl ext file: " + ext_path.string();
            return false;
        }

        ext_file << "authorityKeyIdentifier=keyid,issuer\n";
        ext_file << "basicConstraints=CA:FALSE\n";
        ext_file << "keyUsage=digitalSignature,keyEncipherment\n";
        ext_file << "extendedKeyUsage=serverAuth\n";
        ext_file << "subjectAltName=DNS:" << host_name << "\n";
    }

    const std::string quoted_openssl = "\"" + openssl_bin_path + "\"";
    const std::string create_csr_command = quoted_openssl +
        " req -new -newkey rsa:2048 -nodes -keyout \"" + leaf_key_path.string() + "\"" +
        " -subj \"/CN=" + host_name + "\"" +
        " -out \"" + csr_path.string() + "\"";
    if (!execute_command(create_csr_command, error_message)) {
        return false;
    }

    const std::string sign_command = quoted_openssl +
        " x509 -req -in \"" + csr_path.string() + "\"" +
        " -CA \"" + ca_cert_path.string() + "\"" +
        " -CAkey \"" + ca_key_path.string() + "\"" +
        " -CAcreateserial -out \"" + leaf_cert_path.string() + "\"" +
        " -days 365 -sha256 -extfile \"" + ext_path.string() + "\"";
    if (!execute_command(sign_command, error_message)) {
        return false;
    }

    std::error_code remove_error;
    std::filesystem::remove(csr_path, remove_error);
    std::filesystem::remove(ext_path, remove_error);

    if (!std::filesystem::exists(leaf_cert_path) || !std::filesystem::exists(leaf_key_path)) {
        error_message = "leaf certificate generation did not produce expected files";
        return false;
    }

    return true;
}

}  // namespace network_proxy
