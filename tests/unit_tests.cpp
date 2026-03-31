#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "protocol/http_types.h"
#include "protocol/protocol_detector.h"
#include "transport/tcp_reassembly_buffer.h"

namespace {

bool test_patch_engine_text_patch() {
    network_proxy::AppConfig config;
    config.enable_text_patch = true;
    config.enable_hex_patch = false;
    config.outbound_find = "hello";
    config.outbound_replace = "patched_hello";

    network_proxy::Logger logger;
    network_proxy::PatchEngine patch_engine(config, logger);

    std::string payload = "hello world";
    const bool changed = patch_engine.apply_transport_patch(payload, "tcp", "outbound");
    return changed && payload == "patched_hello world";
}

bool test_patch_engine_hex_patch() {
    network_proxy::AppConfig config;
    config.enable_text_patch = false;
    config.enable_hex_patch = true;
    config.inbound_find_hex = "68656c6c6f";
    config.inbound_replace_hex = "776f726c64";

    network_proxy::Logger logger;
    network_proxy::PatchEngine patch_engine(config, logger);

    std::string payload = "hello";
    const bool changed = patch_engine.apply_transport_patch(payload, "tcp", "inbound");
    return changed && payload == "world";
}

bool test_protocol_detector() {
    const auto http_kind = network_proxy::detect_protocol_kind("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    const std::string tls_hello{"\x16\x03\x01\x00\x10", 5};
    const auto https_kind = network_proxy::detect_protocol_kind(tls_hello);
    const auto unknown_kind = network_proxy::detect_protocol_kind("binary");

    return http_kind == network_proxy::ProtocolKind::Http
        && https_kind == network_proxy::ProtocolKind::Https
        && unknown_kind == network_proxy::ProtocolKind::Unknown;
}

bool test_tcp_reassembly_buffer_http_message() {
    network_proxy::TcpReassemblyBuffer buffer;
    buffer.append("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel");

    std::string message;
    if (buffer.try_take_http_message(message)) {
        return false;
    }

    buffer.append("lo");
    if (!buffer.try_take_http_message(message)) {
        return false;
    }

    return message == "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" && buffer.empty();
}

bool test_app_config_load() {
    const std::filesystem::path config_path = "tmp_test_config.yaml";
    std::ofstream output(config_path, std::ios::trunc);
    output << "tcp:\n";
    output << "  enabled: true\n";
    output << "  listen_host: 127.0.0.1\n";
    output << "  listen_port: 19080\n";
    output << "runtime:\n";
    output << "  dry_run: true\n";
    output << "patch:\n";
    output << "  outbound_find: hello\n";
    output << "  outbound_replace: patched_hello\n";
    output.close();

    network_proxy::AppConfig config;
    std::string error;
    const bool loaded = config.load_from_file(config_path, error);

    std::error_code ec;
    std::filesystem::remove(config_path, ec);

    return loaded && config.tcp_enabled && config.tcp_listen_port == 19080 && config.dry_run && config.outbound_find == "hello";
}

}  // namespace

int main() {
    int failed = 0;

    auto run = [&failed](const char* name, bool (*test_fn)()) {
        const bool ok = test_fn();
        std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << '\n';
        if (!ok) {
            ++failed;
        }
    };

    run("patch_engine_text_patch", test_patch_engine_text_patch);
    run("patch_engine_hex_patch", test_patch_engine_hex_patch);
    run("protocol_detector", test_protocol_detector);
    run("tcp_reassembly_buffer_http_message", test_tcp_reassembly_buffer_http_message);
    run("app_config_load", test_app_config_load);

    if (failed != 0) {
        std::cout << "unit tests failed: " << failed << '\n';
        return 1;
    }

    std::cout << "all unit tests passed" << '\n';
    return 0;
}
