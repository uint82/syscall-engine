#include "syscall/trampoline.hpp"

#include "syscall/stub_layout.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace syscall {
namespace {

std::array<std::uint8_t, kDirectStubSize> assemble_direct(std::uint32_t ssn) {
    std::array<std::uint8_t, kDirectStubSize> stub{};
    std::copy(kStubPrefix.begin(), kStubPrefix.end(), stub.begin());
    std::memcpy(stub.data() + kStubPrefix.size(), &ssn, sizeof(ssn));
    const std::size_t tail = kStubPrefix.size() + sizeof(ssn);
    stub[tail] = kSyscallOpcode0;
    stub[tail + 1] = kSyscallOpcode1;
    stub[tail + kSyscallInstructionLength] = kReturnOpcode;
    return stub;
}

std::array<std::uint8_t, kIndirectStubSize> assemble_indirect(
    std::uint32_t ssn,
    std::uint64_t gadget_address) {
    std::array<std::uint8_t, kIndirectStubSize> stub{};
    std::copy(kStubPrefix.begin(), kStubPrefix.end(), stub.begin());
    std::memcpy(stub.data() + kStubPrefix.size(), &ssn, sizeof(ssn));
    const std::size_t jump = kStubPrefix.size() + sizeof(ssn);
    // FF 25 00 00 00 00 jumps through the 8-byte address parked right behind
    // it, so the stub works at any distance from ntdll.
    stub[jump] = kJumpRipOpcode0;
    stub[jump + 1] = kJumpRipOpcode1;
    std::memcpy(stub.data() + jump + kJumpRipLength, &gadget_address,
                sizeof(gadget_address));
    return stub;
}

}

bool write_direct_stub(std::span<std::uint8_t> destination, std::uint32_t ssn) {
    if (destination.size() < kDirectStubSize) {
        return false;
    }
    const auto stub = assemble_direct(ssn);
    std::copy(stub.begin(), stub.end(), destination.begin());
    return true;
}

bool write_indirect_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t gadget_address) {
    if (destination.size() < kIndirectStubSize) {
        return false;
    }
    const auto stub = assemble_indirect(ssn, gadget_address);
    std::copy(stub.begin(), stub.end(), destination.begin());
    return true;
}

}
