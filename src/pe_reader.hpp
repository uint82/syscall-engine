#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

namespace syscall::pe {

template <typename T>
std::optional<T> read_struct(const std::uint8_t* image, std::size_t size, std::size_t offset) {
    if (image == nullptr || offset > size || size - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value{};
    std::memcpy(&value, image + offset, sizeof(T));
    return value;
}

}
