#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "syscall/pe_image.hpp"
#include "syscall/pe_types.hpp"

namespace support {

inline constexpr std::size_t kHeaderWindow = 0x1000;

struct LiveImage {
    HMODULE module = nullptr;
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0;
};

inline LiveImage live_ntdll() {
    const HMODULE module = GetModuleHandleW(L"ntdll.dll");
    if (module == nullptr) {
        return {};
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(module);
    const auto size = syscall::pe::read_image_size(bytes, kHeaderWindow);
    if (!size.has_value()) {
        return {};
    }
    return {module, bytes, *size};
}

inline std::optional<std::vector<syscall::pe::SectionHeader>> live_sections(
    const LiveImage& image) {
    if (image.bytes == nullptr) {
        return std::nullopt;
    }
    return syscall::pe::read_sections(image.bytes, image.size);
}

}
