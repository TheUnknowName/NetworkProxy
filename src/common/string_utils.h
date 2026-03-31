#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace network_proxy {

std::string trim_copy(std::string_view value);
std::string to_lower_copy(std::string_view value);
std::optional<std::pair<std::string, std::string>> split_once(std::string_view value, char delimiter);

}  // namespace network_proxy
