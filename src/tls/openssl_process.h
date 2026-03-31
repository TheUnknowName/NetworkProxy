#pragma once

#include <cstddef>
#include <string>

namespace network_proxy {

class OpenSslProcess {
public:
    OpenSslProcess() = default;
    OpenSslProcess(const OpenSslProcess&) = delete;
    OpenSslProcess& operator=(const OpenSslProcess&) = delete;
    ~OpenSslProcess();

    bool start(const std::string& command_line, std::string& error_message);
    bool write_stdin(const char* data, std::size_t length, std::string& error_message) const;
    bool read_stdout(std::string& chunk, std::string& error_message, std::size_t max_bytes = 4096) const;
    void close_stdin();
    void stop();
    bool is_running() const;

private:
    void* process_handle_ = nullptr;
    void* thread_handle_ = nullptr;
    void* stdin_write_handle_ = nullptr;
    void* stdout_read_handle_ = nullptr;
};

}  // namespace network_proxy
