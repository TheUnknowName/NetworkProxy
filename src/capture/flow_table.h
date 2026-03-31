#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace network_proxy {

class FlowTable {
public:
    void remember_mapping(std::uint8_t protocol, std::uint32_t source_ip_network_order, std::uint16_t source_port, std::uint32_t destination_ip_network_order, std::uint16_t destination_port);

    std::optional<std::pair<std::string, std::uint16_t>> try_get_upstream(std::uint8_t protocol, std::uint32_t source_ip_network_order, std::uint16_t source_port);

private:
    struct FlowEntry {
        std::uint32_t destination_ip_network_order = 0;
        std::uint16_t destination_port = 0;
        long long touched_millis = 0;
    };

    struct FlowKey {
        std::uint8_t protocol = 0;
        std::uint32_t source_ip_network_order = 0;
        std::uint16_t source_port = 0;

        bool operator==(const FlowKey& other) const {
            return protocol == other.protocol && source_ip_network_order == other.source_ip_network_order && source_port == other.source_port;
        }
    };

    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& key) const;
    };

    void prune_expired_locked(long long now_millis);
    static long long now_millis();
    static std::string ipv4_to_string(std::uint32_t ipv4_network_order);

    static constexpr long long k_entry_ttl_millis = 120000;

    std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> table_;
    std::mutex mutex_;
};

}  // namespace network_proxy
