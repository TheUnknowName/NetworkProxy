#pragma once

#include <mutex>
#include <string>

namespace network_proxy {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error,
};

LogLevel parse_log_level(const std::string& value);

class Logger {
public:
    void set_level(LogLevel level);

    void debug(const std::string& message);
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);

private:
    void log(LogLevel level, const std::string& message);
    static std::string to_string(LogLevel level);

    LogLevel level_ = LogLevel::Info;
    std::mutex mutex_;
};

}  // namespace network_proxy
