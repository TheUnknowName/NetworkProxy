cmake_minimum_required(VERSION 3.24)

project(network_proxy VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(network_proxy
    src/main.cpp
    src/app/application.cpp
    src/common/string_utils.cpp
    src/config/app_config.cpp
    src/logging/logger.cpp
    src/patch/patch_engine.cpp
    src/proxy/proxy_server.cpp
)

target_include_directories(network_proxy
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(network_proxy PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(network_proxy PRIVATE -Wall -Wextra -Wpedantic)
endif()
