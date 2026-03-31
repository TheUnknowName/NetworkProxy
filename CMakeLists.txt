cmake_minimum_required(VERSION 3.24)

project(network_proxy VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

add_executable(network_proxy
    src/main.cpp
    src/app/application.cpp
    src/capture/win_divert_capture.cpp
    src/common/string_utils.cpp
    src/config/app_config.cpp
    src/logging/logger.cpp
    src/patch/patch_engine.cpp
    src/protocol/http_protocol_adapter.cpp
    src/protocol/protocol_detector.cpp
    src/protocol/protocol_manager.cpp
    src/proxy/proxy_server.cpp
    src/rules/rule_engine.cpp
    src/tls/https_mitm_proxy.cpp
    src/tls/openssl_process.cpp
    src/tls/certificate_manager.cpp
    src/transport/socket_utils.cpp
    src/transport/tcp_reassembly_buffer.cpp
    src/transport/tcp_proxy_server.cpp
    src/transport/udp_proxy_server.cpp
)

target_include_directories(network_proxy
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(network_proxy PRIVATE ws2_32)

if(MSVC)
    target_compile_options(network_proxy PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(network_proxy PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(network_proxy_unit_tests
    tests/unit_tests.cpp
    src/common/string_utils.cpp
    src/config/app_config.cpp
    src/logging/logger.cpp
    src/patch/patch_engine.cpp
    src/protocol/protocol_detector.cpp
    src/rules/rule_engine.cpp
    src/transport/tcp_reassembly_buffer.cpp
)

target_include_directories(network_proxy_unit_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(network_proxy_unit_tests PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(network_proxy_unit_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME unit_tests COMMAND network_proxy_unit_tests)
add_test(
    NAME smoke_tests
    COMMAND powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/tools/smoke_test.ps1
)
add_test(
    NAME packet_smoke_tests
    COMMAND powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/tools/packet_smoke_test.ps1
)
add_test(
    NAME e2e_validation
    COMMAND powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/tools/e2e_clean_validation.ps1
)
