#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "syscall/pe_types.hpp"
#include "syscall/stub_layout.hpp"
#include "syscall/unwind.hpp"

namespace syscall {

inline constexpr std::array<std::uint8_t, 3> kSyscallGadget{0x0F, 0x05, 0xC3};
inline constexpr std::array<std::uint8_t, 2> kLeaveRetGadget{0xC9, 0xC3};

struct SpoofGadgets {
    std::array<std::uint32_t, kSpoofFrameCount> frames{};
    std::uint32_t terminator = 0;
};

struct UnwindSpoofGadgets {
    std::uint32_t syscall = 0;
    std::array<std::uint32_t, kUnwindGadgetCount> frames{};
};

// An empty pattern would match everything, so it is rejected.
bool matches_bytes_at(
    std::span<const std::uint8_t> image,
    std::uint32_t rva,
    std::span<const std::uint8_t> expected);

std::optional<std::uint32_t> find_syscall_gadget(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections);
std::optional<std::uint32_t> find_leaf_syscall_gadget(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions);
std::optional<SpoofGadgets> find_spoof_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections);
std::optional<UnwindSpoofGadgets> find_unwind_spoof_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions);

}
