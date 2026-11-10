#include "syscall/trampoline.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace syscall {
namespace {

class ByteWriter {
public:
    explicit ByteWriter(std::span<std::uint8_t> destination) : destination_(destination) {}

    void write_u8(std::uint8_t value) {
        destination_[offset_++] = value;
    }

    void write_u32(std::uint32_t value) {
        write_value(value);
    }

    void write_u64(std::uint64_t value) {
        write_value(value);
    }

    void write_bytes(std::span<const std::uint8_t> bytes) {
        std::copy(bytes.begin(), bytes.end(), destination_.begin() + offset_);
        offset_ += bytes.size();
    }

private:
    template <typename T>
    void write_value(T value) {
        std::memcpy(destination_.data() + offset_, &value, sizeof(value));
        offset_ += sizeof(value);
    }

    std::span<std::uint8_t> destination_;
    std::size_t offset_ = 0;
};

void write_syscall_prefix(ByteWriter& writer, std::uint32_t ssn) {
    writer.write_bytes(kStubPrefix);
    writer.write_u32(ssn);
}

void write_indirect_jump(ByteWriter& writer, std::uint64_t gadget_address) {
    writer.write_u8(kJumpRipOpcode0);
    writer.write_u8(kJumpRipOpcode1);
    writer.write_u32(0);
    writer.write_u64(gadget_address);
}

void write_mov_rax(ByteWriter& writer, std::uint64_t value) {
    writer.write_bytes(kMovRaxImm64Opcode);
    writer.write_u64(value);
}

void write_store_rax(ByteWriter& writer, std::size_t offset) {
    if (offset == 0) {
        writer.write_bytes(kStoreRaxAtRspOpcode);
        return;
    }
    writer.write_bytes(kStoreRaxAtRspDisp8Opcode);
    writer.write_u8(static_cast<std::uint8_t>(offset));
}

void write_load_rax(ByteWriter& writer, std::size_t offset) {
    writer.write_bytes(kLoadRaxAtRspDisp32Opcode);
    writer.write_u32(static_cast<std::uint32_t>(offset));
}

void write_spoofed_prologue(ByteWriter& writer) {
    writer.write_u8(kPushRbpOpcode);
    writer.write_bytes(kMovRbpRspOpcode);
    writer.write_bytes(kSubRspOpcode);
    writer.write_u32(static_cast<std::uint32_t>(kSpoofFrameSize));
}

void write_spoof_slots(ByteWriter& writer, const SpoofAddresses& addresses) {
    for (std::size_t index = 0; index < kSpoofFrameCount; ++index) {
        write_mov_rax(writer, addresses.frames[index]);
        write_store_rax(writer, index * sizeof(std::uint64_t));
    }
    write_mov_rax(writer, addresses.terminator);
    write_store_rax(writer, kSpoofFrameCount * sizeof(std::uint64_t));
}

void write_stack_args(ByteWriter& writer) {
    for (std::size_t index = 0; index < kSpoofArgCount; ++index) {
        write_load_rax(writer, kSpoofArgSourceOffset + index * sizeof(std::uint64_t));
        write_store_rax(writer, kSpoofArgOffset + index * sizeof(std::uint64_t));
    }
}

void write_unwind_prologue(ByteWriter& writer) {
    writer.write_bytes(kSubRspImm8Opcode);
    writer.write_u8(static_cast<std::uint8_t>(kUnwindFrameSize));
}

void write_unwind_slots(ByteWriter& writer, const UnwindSpoofAddresses& addresses) {
    for (std::size_t index = 0; index < kUnwindFrameCount; ++index) {
        write_mov_rax(writer, addresses.frames[index]);
        write_store_rax(writer, index * sizeof(std::uint64_t));
    }
}

void write_unwind_args(ByteWriter& writer) {
    for (std::size_t index = 0; index < kUnwindArgCount; ++index) {
        writer.write_bytes(kLoadR10AtRspDisp32Opcode);
        writer.write_u32(static_cast<std::uint32_t>(
            kUnwindArgSourceOffset + index * sizeof(std::uint64_t)));
        writer.write_bytes(kStoreR10AtRspDisp8Opcode);
        writer.write_u8(static_cast<std::uint8_t>(
            kUnwindArgOffset + index * sizeof(std::uint64_t)));
    }
}

std::array<std::uint8_t, kDirectStubSize> assemble_direct(std::uint32_t ssn) {
    std::array<std::uint8_t, kDirectStubSize> stub{};
    ByteWriter writer(stub);
    write_syscall_prefix(writer, ssn);
    writer.write_u8(kSyscallOpcode0);
    writer.write_u8(kSyscallOpcode1);
    writer.write_u8(kReturnOpcode);
    return stub;
}

std::array<std::uint8_t, kIndirectStubSize> assemble_indirect(
    std::uint32_t ssn,
    std::uint64_t gadget_address) {
    std::array<std::uint8_t, kIndirectStubSize> stub{};
    ByteWriter writer(stub);
    write_syscall_prefix(writer, ssn);
    write_indirect_jump(writer, gadget_address);
    return stub;
}

std::array<std::uint8_t, kSpoofStubSize> assemble_spoofed(
    std::uint32_t ssn,
    std::uint64_t gadget_address,
    const SpoofAddresses& addresses) {
    std::array<std::uint8_t, kSpoofStubSize> stub{};
    ByteWriter writer(stub);
    write_spoofed_prologue(writer);
    write_spoof_slots(writer, addresses);
    write_stack_args(writer);
    write_syscall_prefix(writer, ssn);
    write_indirect_jump(writer, gadget_address);
    return stub;
}

std::array<std::uint8_t, kUnwindStubSize> assemble_unwind_spoofed(
    std::uint32_t ssn,
    std::uint64_t syscall_gadget,
    const UnwindSpoofAddresses& addresses) {
    std::array<std::uint8_t, kUnwindStubSize> stub{};
    ByteWriter writer(stub);
    write_unwind_prologue(writer);
    write_unwind_slots(writer, addresses);
    write_unwind_args(writer);
    write_syscall_prefix(writer, ssn);
    write_indirect_jump(writer, syscall_gadget);
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

bool write_spoofed_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t gadget_address,
    const SpoofAddresses& addresses) {
    if (destination.size() < kSpoofStubSize) {
        return false;
    }
    const auto stub = assemble_spoofed(ssn, gadget_address, addresses);
    std::copy(stub.begin(), stub.end(), destination.begin());
    return true;
}

bool write_unwind_spoofed_stub(
    std::span<std::uint8_t> destination,
    std::uint32_t ssn,
    std::uint64_t syscall_gadget,
    const UnwindSpoofAddresses& addresses) {
    if (destination.size() < kUnwindStubSize) {
        return false;
    }
    const auto stub = assemble_unwind_spoofed(ssn, syscall_gadget, addresses);
    std::copy(stub.begin(), stub.end(), destination.begin());
    return true;
}

}
