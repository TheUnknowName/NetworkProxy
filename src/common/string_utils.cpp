#include "common/string_utils.h"

#include <algorithm>
#include <cctype>

namespace network_proxy {

std::string trim_copy(std::string_view value) {
    std::size_t begin = 0;
    std::size_t end = value.size();

    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return std::string(value.substr(begin, end - begin));
}

std::string to_lower_copy(std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::optional<std::pair<std::string, std::string>> split_once(std::string_view value, char delimiter) {
    const std::size_t position = value.find(delimiter);
    if (position == std::string_view::npos) {
        return std::nullopt;
    }

    return std::make_pair(
        std::string(value.substr(0, position)),
        std::string(value.substr(position + 1)));
}

}  // namespace network_proxy
