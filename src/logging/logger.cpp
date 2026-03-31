#include "logging/logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "common/string_utils.h"

namespace network_proxy {

LogLevel parse_log_level(const std::string& value) {
    const std::string normalized = to_lower_copy(value);
    if (normalized == "debug") {
        return LogLevel::Debug;
    }

    if (normalized == "warn") {
        return LogLevel::Warn;
    }

    if (normalized == "error") {
        return LogLevel::Error;
    }

    return LogLevel::Info;
}

void Logger::set_level(LogLevel level) {
    level_ = level;
}

void Logger::debug(const std::string& message) {
    log(LogLevel::Debug, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::Info, message);
}

void Logger::warn(const std::string& message) {
    log(LogLevel::Warn, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::Error, message);
}

void Logger::log(LogLevel level, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(level_)) {
        return;
    }

    const auto now = std::chrono::system_clock::now();
    const std::time_t time_value = std::chrono::system_clock::to_time_t(now);

    std::tm time_info{};
#if defined(_WIN32)
    localtime_s(&time_info, &time_value);
#else
    localtime_r(&time_value, &time_info);
#endif

    std::ostringstream output_stream;
    output_stream << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S")
                  << " [" << to_string(level) << "] "
                  << message;

    std::scoped_lock lock(mutex_);
    std::cout << output_stream.str() << std::endl;
}

std::string Logger::to_string(LogLevel level) {
    switch (level) {
    case LogLevel::Debug:
        return "debug";
    case LogLevel::Info:
        return "info";
    case LogLevel::Warn:
        return "warn";
    case LogLevel::Error:
        return "error";
    }

    return "info";
}

}  // namespace network_proxy
