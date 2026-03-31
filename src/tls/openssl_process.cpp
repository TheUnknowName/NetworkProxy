#include "tls/openssl_process.h"

#include <vector>

#include <Windows.h>

namespace network_proxy {

namespace {

void close_handle(void*& handle) {
    if (handle != nullptr) {
        CloseHandle(static_cast<HANDLE>(handle));
        handle = nullptr;
    }
}

}  // namespace

OpenSslProcess::~OpenSslProcess() {
    stop();
}

bool OpenSslProcess::start(const std::string& command_line, std::string& error_message) {
    stop();

    SECURITY_ATTRIBUTES security_attributes{};
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.bInheritHandle = TRUE;

    HANDLE child_stdout_read = nullptr;
    HANDLE child_stdout_write = nullptr;
    if (!CreatePipe(&child_stdout_read, &child_stdout_write, &security_attributes, 0)) {
        error_message = "CreatePipe stdout failed";
        return false;
    }

    HANDLE child_stdin_read = nullptr;
    HANDLE child_stdin_write = nullptr;
    if (!CreatePipe(&child_stdin_read, &child_stdin_write, &security_attributes, 0)) {
        CloseHandle(child_stdout_read);
        CloseHandle(child_stdout_write);
        error_message = "CreatePipe stdin failed";
        return false;
    }

    SetHandleInformation(child_stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(child_stdin_write, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA startup_info{};
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = child_stdin_read;
    startup_info.hStdOutput = child_stdout_write;
    startup_info.hStdError = child_stdout_write;

    PROCESS_INFORMATION process_info{};
    std::vector<char> command_buffer(command_line.begin(), command_line.end());
    command_buffer.push_back('\0');

    const BOOL created = CreateProcessA(
        nullptr,
        command_buffer.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup_info,
        &process_info);

    CloseHandle(child_stdin_read);
    CloseHandle(child_stdout_write);

    if (created == FALSE) {
        CloseHandle(child_stdout_read);
        CloseHandle(child_stdin_write);
        error_message = "CreateProcess failed";
        return false;
    }

    process_handle_ = process_info.hProcess;
    thread_handle_ = process_info.hThread;
    stdout_read_handle_ = child_stdout_read;
    stdin_write_handle_ = child_stdin_write;
    return true;
}

bool OpenSslProcess::write_stdin(const char* data, std::size_t length, std::string& error_message) const {
    if (stdin_write_handle_ == nullptr || data == nullptr || length == 0) {
        return true;
    }

    std::size_t total_written = 0;
    while (total_written < length) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(length - total_written);
        if (!WriteFile(static_cast<HANDLE>(stdin_write_handle_), data + total_written, chunk, &written, nullptr)) {
            error_message = "WriteFile stdin failed";
            return false;
        }

        if (written == 0) {
            error_message = "WriteFile stdin wrote 0";
            return false;
        }

        total_written += static_cast<std::size_t>(written);
    }

    return true;
}

bool OpenSslProcess::read_stdout(std::string& chunk, std::string& error_message, std::size_t max_bytes) const {
    chunk.clear();
    if (stdout_read_handle_ == nullptr || max_bytes == 0) {
        return false;
    }

    std::vector<char> buffer(max_bytes);
    DWORD read_count = 0;
    const BOOL ok = ReadFile(static_cast<HANDLE>(stdout_read_handle_), buffer.data(), static_cast<DWORD>(buffer.size()), &read_count, nullptr);
    if (ok == FALSE) {
        const DWORD last_error = GetLastError();
        if (last_error == ERROR_BROKEN_PIPE) {
            return false;
        }

        error_message = "ReadFile stdout failed";
        return false;
    }

    if (read_count == 0) {
        return false;
    }

    chunk.assign(buffer.data(), buffer.data() + read_count);
    return true;
}

void OpenSslProcess::close_stdin() {
    close_handle(stdin_write_handle_);
}

bool OpenSslProcess::is_running() const {
    if (process_handle_ == nullptr) {
        return false;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &exit_code)) {
        return false;
    }

    return exit_code == STILL_ACTIVE;
}

void OpenSslProcess::stop() {
    close_stdin();
    close_handle(stdout_read_handle_);

    if (process_handle_ != nullptr) {
        HANDLE handle = static_cast<HANDLE>(process_handle_);
        DWORD exit_code = 0;
        if (GetExitCodeProcess(handle, &exit_code) && exit_code == STILL_ACTIVE) {
            TerminateProcess(handle, 1);
            WaitForSingleObject(handle, 2000);
        }
    }

    close_handle(thread_handle_);
    close_handle(process_handle_);
}

}  // namespace network_proxy
