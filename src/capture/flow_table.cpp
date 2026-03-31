#include "capture/flow_table.h"

#include <chrono>
#include <functional>

namespace network_proxy {

std::size_t FlowTable::FlowKeyHash::operator()(const FlowKey& key) const {
    std::size_t hash_value = static_cast<std::size_t>(key.protocol);
    hash_value ^= std::hash<std::string>{}(key.source_ip) + 0x9e3779b9 + (hash_value << 6U) + (hash_value >> 2U);
    hash_value ^= static_cast<std::size_t>(key.source_port) + 0x9e3779b9 + (hash_value << 6U) + (hash_value >> 2U);
    return hash_value;
}

void FlowTable::remember_mapping(
    std::uint8_t protocol,
    const std::string& source_ip,
    std::uint16_t source_port,
    const std::string& destination_host,
    std::uint16_t destination_port) {
    const long long now = now_millis();

    std::lock_guard<std::mutex> lock(mutex_);
    FlowKey key{protocol, source_ip, source_port};
    table_[key] = FlowEntry{destination_host, destination_port, now};

    if (table_.size() > 4096U) {
        prune_expired_locked(now);
    }
}

std::optional<std::pair<std::string, std::uint16_t>> FlowTable::try_get_upstream(
    std::uint8_t protocol,
    const std::string& source_ip,
    std::uint16_t source_port) {
    const long long now = now_millis();

    std::lock_guard<std::mutex> lock(mutex_);
    FlowKey key{protocol, source_ip, source_port};
    const auto iterator = table_.find(key);
    if (iterator == table_.end()) {
        return std::nullopt;
    }

    if ((now - iterator->second.touched_millis) > k_entry_ttl_millis) {
        table_.erase(iterator);
        return std::nullopt;
    }

    iterator->second.touched_millis = now;
    return std::make_optional(std::make_pair(iterator->second.destination_host, iterator->second.destination_port));
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

}  // namespace network_proxy
