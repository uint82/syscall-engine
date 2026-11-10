#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "syscall/stub_layout.hpp"

namespace syscall {

struct SpoofAddresses {
    std::array<std::uint64_t, kSpoofFrameCount> frames{};
    std::uint64_t terminator = 0;
};

bool write_direct_stub(std::span<std::uint8_t> destination, std::uint32_t ssn);
bool write_indirect_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t gadget_address);
bool write_spoofed_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t gadget_address,
    const SpoofAddresses& addresses);

}
