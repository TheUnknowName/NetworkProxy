#pragma once

#include <atomic>

#include "capture/flow_table.h"
#include "config/app_config.h"
#include "logging/logger.h"

namespace network_proxy {

struct WindivertAddress {
    unsigned char raw[64]{};
};

class WinDivertCapture {
public:
    WinDivertCapture(const AppConfig& config, Logger& logger, FlowTable& flow_table);
    ~WinDivertCapture();

    bool initialize();
    void run(std::atomic_bool& stop_requested);

private:
    bool bind_functions();
    bool rewrite_packet_to_local_proxy(unsigned char* packet_data, unsigned int packet_length) const;

    const AppConfig& config_;
    Logger& logger_;
    FlowTable& flow_table_;
    void* module_handle_ = nullptr;
    void* divert_handle_ = nullptr;

    using windivert_open_fn = void*(__stdcall*)(const char* filter, unsigned short layer, short priority, unsigned long long flags);
    using windivert_close_fn = int(__stdcall*)(void* handle);
    using windivert_recv_fn = int(__stdcall*)(void* handle, void* packet, unsigned int packet_length, unsigned int* receive_length, void* address);
    using windivert_send_fn = int(__stdcall*)(void* handle, void* packet, unsigned int packet_length, unsigned int* send_length, void* address);
    using windivert_calc_checksums_fn = unsigned int(__stdcall*)(void* packet, unsigned int packet_length, void* address, unsigned long long flags);

    windivert_open_fn windivert_open_ = nullptr;
    windivert_close_fn windivert_close_ = nullptr;
    windivert_recv_fn windivert_recv_ = nullptr;
    windivert_send_fn windivert_send_ = nullptr;
    windivert_calc_checksums_fn windivert_calc_checksums_ = nullptr;
};

}  // namespace network_proxy
