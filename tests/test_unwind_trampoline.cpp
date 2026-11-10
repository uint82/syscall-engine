#include "test_harness.hpp"

#include "syscall/stub_layout.hpp"
#include "syscall/trampoline.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace {

constexpr std::uint32_t kSampleSsn = 0x12345678;
constexpr std::uint64_t kSampleSyscallGadget = 0x00007FF812345678;
constexpr std::array<std::uint64_t, syscall::kUnwindGadgetCount> kSampleFrames{
    0x00007FF8AABBCC01,
    0x00007FF8AABBCC02,
    0x00007FF8AABBCC03,
    0x00007FF8AABBCC04,
    0x00007FF8AABBCC05};

syscall::UnwindSpoofAddresses sample_addresses() {
    syscall::UnwindSpoofAddresses addresses{};
    addresses.frames = kSampleFrames;
    return addresses;
}

std::vector<std::uint8_t> encode_u32(std::uint32_t value) {
    std::vector<std::uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

std::vector<std::uint8_t> encode_u64(std::uint64_t value) {
    std::vector<std::uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

template <std::size_t Size>
bool contains(
    const std::array<std::uint8_t, Size>& stub,
    const std::vector<std::uint8_t>& pattern) {
    return std::search(stub.begin(), stub.end(), pattern.begin(), pattern.end()) !=
           stub.end();
}

std::size_t prologue_size() {
    return syscall::kPushRbpLength + syscall::kMovRbpRspLength +
           syscall::kSubRspImm32Length + syscall::kSubRbpImm8Length;
}

std::size_t slot_size() {
    return syscall::kMovRaxImm64Length + syscall::kStoreRaxAtRspLength;
}

std::size_t record_size() {
    return syscall::kLeaRaxRbpDisp8Length + syscall::kStoreRaxAtRbpDisp8Length +
           syscall::kMovRaxImm64Length + syscall::kStoreRaxAtRbpDisp8Length;
}

std::vector<std::uint8_t> expected_record(
    std::size_t index,
    std::uint64_t gadget) {
    const auto record_offset =
        static_cast<std::uint8_t>(index * syscall::kUnwindFrameStep);
    const auto saved_offset =
        static_cast<std::uint8_t>(record_offset + syscall::kUnwindFrameStep);
    std::vector<std::uint8_t> record;
    record.insert(
        record.end(), syscall::kLeaRaxRbpDisp8Opcode.begin(),
        syscall::kLeaRaxRbpDisp8Opcode.end());
    record.push_back(saved_offset);
    record.insert(
        record.end(), syscall::kStoreRaxAtRbpDisp8Opcode.begin(),
        syscall::kStoreRaxAtRbpDisp8Opcode.end());
    record.push_back(record_offset);
    record.insert(
        record.end(), syscall::kMovRaxImm64Opcode.begin(),
        syscall::kMovRaxImm64Opcode.end());
    const auto gadget_bytes = encode_u64(gadget);
    record.insert(record.end(), gadget_bytes.begin(), gadget_bytes.end());
    record.insert(
        record.end(), syscall::kStoreRaxAtRbpDisp8Opcode.begin(),
        syscall::kStoreRaxAtRbpDisp8Opcode.end());
    record.push_back(
        static_cast<std::uint8_t>(record_offset + sizeof(std::uint64_t)));
    return record;
}

std::vector<std::uint8_t> expected_arg_block() {
    std::vector<std::uint8_t> block;
    for (std::size_t index = 0; index < syscall::kUnwindArgCount; ++index) {
        const auto source = static_cast<std::uint32_t>(
            syscall::kUnwindArgSourceOffset + index * sizeof(std::uint64_t));
        const auto destination = static_cast<std::uint8_t>(
            syscall::kUnwindArgOffset + index * sizeof(std::uint64_t));
        block.insert(
            block.end(), syscall::kLoadR10AtRspDisp32Opcode.begin(),
            syscall::kLoadR10AtRspDisp32Opcode.end());
        const auto source_bytes = encode_u32(source);
        block.insert(block.end(), source_bytes.begin(), source_bytes.end());
        block.insert(
            block.end(), syscall::kStoreR10AtRspDisp8Opcode.begin(),
            syscall::kStoreR10AtRspDisp8Opcode.end());
        block.push_back(destination);
    }
    return block;
}

}

SC_TEST_CASE("write_unwind_spoofed_stub emits the expected prologue") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    const std::array<std::uint8_t, 15> prologue{
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0xB0,
        0x00, 0x00, 0x00, 0x48, 0x83, 0xED, 0x40};
    SC_REQUIRE(std::equal(prologue.begin(), prologue.end(), stub.begin()));
}

SC_TEST_CASE("write_unwind_spoofed_stub stores the leave gadget below the records") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    std::vector<std::uint8_t> expected;
    expected.insert(
        expected.end(), syscall::kMovRaxImm64Opcode.begin(),
        syscall::kMovRaxImm64Opcode.end());
    const auto gadget = encode_u64(kSampleFrames[0]);
    expected.insert(expected.end(), gadget.begin(), gadget.end());
    expected.insert(
        expected.end(), syscall::kStoreRaxAtRspOpcode.begin(),
        syscall::kStoreRaxAtRspOpcode.end());
    SC_REQUIRE(std::equal(
        expected.begin(), expected.end(), stub.begin() + prologue_size()));
}

SC_TEST_CASE("write_unwind_spoofed_stub emits the expected record chain") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    std::size_t offset = prologue_size() + slot_size();
    for (std::size_t index = 0; index < syscall::kUnwindFrameCount; ++index) {
        const auto expected = expected_record(index, kSampleFrames[index + 1]);
        SC_REQUIRE(std::equal(expected.begin(), expected.end(), stub.begin() + offset));
        offset += expected.size();
    }
}

SC_TEST_CASE("write_unwind_spoofed_stub copies the caller stack arguments") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    const auto offset = prologue_size() + slot_size() +
                        syscall::kUnwindFrameCount * record_size();
    const auto expected = expected_arg_block();
    SC_REQUIRE(std::equal(expected.begin(), expected.end(), stub.begin() + offset));
}

SC_TEST_CASE("write_unwind_spoofed_stub emits the expected syscall tail") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    const std::array<std::uint8_t, 22> tail{
        0x4C, 0x8B, 0xD1, 0xB8, 0x78, 0x56, 0x34, 0x12,
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0xF8, 0x7F, 0x00, 0x00};
    SC_REQUIRE(std::equal(tail.begin(), tail.end(), stub.end() - tail.size()));
}

SC_TEST_CASE("write_unwind_spoofed_stub embeds every gadget address") {
    std::array<std::uint8_t, syscall::kUnwindStubSize> stub{};
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        stub, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    for (const auto frame : kSampleFrames) {
        SC_REQUIRE(contains(stub, encode_u64(frame)));
    }
    SC_REQUIRE(contains(stub, encode_u64(kSampleSyscallGadget)));
}

SC_TEST_CASE("write_unwind_spoofed_stub rejects a buffer smaller than the stub") {
    std::array<std::uint8_t, syscall::kUnwindStubSize - 1> slot{};
    SC_REQUIRE(!syscall::write_unwind_spoofed_stub(
        slot, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
}

SC_TEST_CASE("write_unwind_spoofed_stub keeps stubs inside their stride") {
    std::array<std::uint8_t, syscall::kTrampolineStride * 2> region{};
    auto slots = std::span<std::uint8_t>(region);
    auto first = slots.first(syscall::kTrampolineStride);
    auto second = slots.subspan(syscall::kTrampolineStride, syscall::kTrampolineStride);

    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        first, 1, 0x1000, sample_addresses()));
    const std::vector<std::uint8_t> first_copy(first.begin(), first.end());

    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        second, 2, 0x2000, sample_addresses()));
    SC_REQUIRE(std::equal(first_copy.begin(), first_copy.end(), first.begin()));
}

SC_TEST_CASE("write_unwind_spoofed_stub does not write past the stub") {
    std::array<std::uint8_t, syscall::kTrampolineStride> slot{};
    slot.fill(0xAA);
    SC_REQUIRE(syscall::write_unwind_spoofed_stub(
        slot, kSampleSsn, kSampleSyscallGadget, sample_addresses()));
    SC_REQUIRE_EQ(0xAA, slot[syscall::kUnwindStubSize]);
}
