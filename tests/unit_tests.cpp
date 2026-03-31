#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "config/app_config.h"
#include "logging/logger.h"
#include "patch/patch_engine.h"
#include "protocol/http_types.h"
#include "protocol/protocol_detector.h"
#include "rules/rule_engine.h"
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

bool test_rule_engine_load_and_transport_match() {
    const std::filesystem::path rules_path = "tmp_test_rules.dsl";
    std::ofstream output(rules_path, std::ios::trunc);
    output << "rule \"tcp-out\" {\n";
    output << "  when.protocol = tcp\n";
    output << "  when.direction = outbound\n";
    output << "  when.remote_port = 7000\n";
    output << "  action.text_find = hello\n";
    output << "  action.text_replace = patched_hello\n";
    output << "}\n";
    output.close();

    network_proxy::RuleEngine engine;
    std::string error;
    const bool loaded = engine.load_from_file(rules_path, error);

    network_proxy::RuleMatchContext context;
    context.protocol = "tcp";
    context.direction = "outbound";
    context.remote_port = 7000;

    std::string payload = "hello dsl";
    const bool changed = loaded && engine.apply_transport(payload, context);

    std::error_code ec;
    std::filesystem::remove(rules_path, ec);

    return loaded && changed && payload == "patched_hello dsl" && engine.rule_count() == 1;
}

bool test_rule_engine_http_header_and_body_patch() {
    const std::filesystem::path rules_path = "tmp_http_rules.dsl";
    std::ofstream output(rules_path, std::ios::trunc);
    output << "rule \"http-post\" {\n";
    output << "  when.protocol = http\n";
    output << "  when.direction = outbound\n";
    output << "  when.method = post\n";
    output << "  when.path_contains = /api\n";
    output << "  action.header_set.X-Test = yes\n";
    output << "  action.body_find = old\n";
    output << "  action.body_replace = new\n";
    output << "}\n";
    output.close();

    network_proxy::RuleEngine engine;
    std::string error;
    const bool loaded = engine.load_from_file(rules_path, error);

    network_proxy::HttpRequest request;
    request.method = "POST";
    request.target = "/api/orders";
    request.body = "old-body";

    network_proxy::RuleMatchContext context;
    context.protocol = "http";
    context.direction = "outbound";
    context.method = "POST";
    context.path = "/api/orders";

    const bool changed = loaded && engine.apply_http_request(request, context);

    std::error_code ec;
    std::filesystem::remove(rules_path, ec);

    return loaded
        && changed
        && request.body == "new-body"
        && request.headers.contains("X-Test")
        && request.headers["X-Test"] == "yes";
}

bool test_patch_engine_with_rule_engine_context() {
    const std::filesystem::path rules_path = "tmp_patch_rules.dsl";
    std::ofstream output(rules_path, std::ios::trunc);
    output << "rule \"ctx\" {\n";
    output << "  when.protocol = tcp\n";
    output << "  when.direction = inbound\n";
    output << "  when.remote_port = 8080\n";
    output << "  action.text_find = alpha\n";
    output << "  action.text_replace = beta\n";
    output << "}\n";
    output.close();

    network_proxy::RuleEngine engine;
    std::string error;
    if (!engine.load_from_file(rules_path, error)) {
        std::error_code ec;
        std::filesystem::remove(rules_path, ec);
        return false;
    }

    network_proxy::AppConfig config;
    config.enable_text_patch = false;
    config.enable_hex_patch = false;
    network_proxy::Logger logger;
    network_proxy::PatchEngine patch_engine(config, logger);
    patch_engine.set_rule_engine(&engine);

    network_proxy::RuleMatchContext context;
    context.protocol = "tcp";
    context.direction = "inbound";
    context.remote_port = 8080;

    std::string payload = "alpha";
    const bool changed = patch_engine.apply_transport_patch(payload, "tcp", "inbound", &context);

    std::error_code ec;
    std::filesystem::remove(rules_path, ec);

    return changed && payload == "beta";
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
    run("rule_engine_load_and_transport_match", test_rule_engine_load_and_transport_match);
    run("rule_engine_http_header_and_body_patch", test_rule_engine_http_header_and_body_patch);
    run("patch_engine_with_rule_engine_context", test_patch_engine_with_rule_engine_context);

    if (failed != 0) {
        std::cout << "unit tests failed: " << failed << '\n';
        return 1;
    }

    std::cout << "all unit tests passed" << '\n';
    return 0;
}
