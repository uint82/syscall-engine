#pragma once

#include <cstdint>
#include <span>

namespace syscall {

bool write_direct_stub(std::span<std::uint8_t> destination, std::uint32_t ssn);
bool write_indirect_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t gadget_address);

}
