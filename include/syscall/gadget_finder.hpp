#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "syscall/pe_types.hpp"

namespace syscall {

inline constexpr std::array<std::uint8_t, 3> kSyscallGadget{0x0F, 0x05, 0xC3};

std::optional<std::uint32_t> find_syscall_gadget(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections);

}
