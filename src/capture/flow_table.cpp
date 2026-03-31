#include "capture/flow_table.h"

#include <chrono>
#include <mutex>
#include <unordered_map>

#include <WinSock2.h>
#include <WS2tcpip.h>

namespace network_proxy {

std::size_t FlowTable::FlowKeyHash::operator()(const FlowKey& key) const {
    std::size_t hash_value = static_cast<std::size_t>(key.protocol);
    hash_value ^= static_cast<std::size_t>(key.source_ip_network_order) + 0x9e3779b9 + (hash_value << 6U) + (hash_value >> 2U);
    hash_value ^= static_cast<std::size_t>(key.source_port) + 0x9e3779b9 + (hash_value << 6U) + (hash_value >> 2U);
    return hash_value;
}

void FlowTable::remember_mapping(
    std::uint8_t protocol,
    std::uint32_t source_ip_network_order,
    std::uint16_t source_port,
    std::uint32_t destination_ip_network_order,
    std::uint16_t destination_port) {
    const long long now = now_millis();

    std::lock_guard<std::mutex> lock(mutex_);
    FlowKey key{protocol, source_ip_network_order, source_port};
    table_[key] = FlowEntry{destination_ip_network_order, destination_port, now};

    if (table_.size() > 4096U) {
        prune_expired_locked(now);
    }
}

std::optional<std::pair<std::string, std::uint16_t>> FlowTable::try_get_upstream(
    std::uint8_t protocol,
    std::uint32_t source_ip_network_order,
    std::uint16_t source_port) {
    const long long now = now_millis();

    std::lock_guard<std::mutex> lock(mutex_);
    FlowKey key{protocol, source_ip_network_order, source_port};
    const auto iterator = table_.find(key);
    if (iterator == table_.end()) {
        return std::nullopt;
    }

    if ((now - iterator->second.touched_millis) > k_entry_ttl_millis) {
        table_.erase(iterator);
        return std::nullopt;
    }

    iterator->second.touched_millis = now;
    return std::make_optional(std::make_pair(ipv4_to_string(iterator->second.destination_ip_network_order), iterator->second.destination_port));
}

void FlowTable::prune_expired_locked(long long now_millis_value) {
    for (auto iterator = table_.begin(); iterator != table_.end();) {
        if ((now_millis_value - iterator->second.touched_millis) > k_entry_ttl_millis) {
            iterator = table_.erase(iterator);
            continue;
        }

        ++iterator;
    }
}

long long FlowTable::now_millis() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

std::string FlowTable::ipv4_to_string(std::uint32_t ipv4_network_order) {
    in_addr address{};
    address.S_un.S_addr = ipv4_network_order;

    char buffer[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &address, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) {
        return "127.0.0.1";
    }

    return std::string(buffer);
}

}  // namespace network_proxy
