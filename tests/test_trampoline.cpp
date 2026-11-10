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
constexpr std::uint64_t kSampleGadget = 0x00007FF812345678;

}

SC_TEST_CASE("write_direct_stub emits the expected byte sequence") {
    std::array<std::uint8_t, syscall::kTrampolineStride> slot{};
    SC_REQUIRE(syscall::write_direct_stub(slot, kSampleSsn));

    const std::array<std::uint8_t, syscall::kDirectStubSize> expected{
        0x4C, 0x8B, 0xD1, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x0F, 0x05, 0xC3};
    SC_REQUIRE(std::equal(expected.begin(), expected.end(), slot.begin()));
}

SC_TEST_CASE("write_direct_stub rejects a buffer smaller than the stub") {
    std::array<std::uint8_t, syscall::kDirectStubSize - 1> slot{};
    SC_REQUIRE(!syscall::write_direct_stub(slot, kSampleSsn));
}

SC_TEST_CASE("write_direct_stub leaves neighboring slots untouched") {
    std::array<std::uint8_t, syscall::kTrampolineStride * 2> region{};
    auto slots = std::span<std::uint8_t>(region);
    auto first = slots.first(syscall::kTrampolineStride);
    auto second = slots.subspan(syscall::kTrampolineStride, syscall::kTrampolineStride);

    SC_REQUIRE(syscall::write_direct_stub(first, 1));
    const std::vector<std::uint8_t> first_copy(first.begin(), first.end());

    SC_REQUIRE(syscall::write_direct_stub(second, 2));
    SC_REQUIRE(std::equal(first_copy.begin(), first_copy.end(), first.begin()));
}

SC_TEST_CASE("write_indirect_stub emits the expected byte sequence") {
    std::array<std::uint8_t, syscall::kTrampolineStride> slot{};
    SC_REQUIRE(syscall::write_indirect_stub(slot, kSampleSsn, kSampleGadget));

    const std::array<std::uint8_t, syscall::kIndirectStubSize> expected{
        0x4C, 0x8B, 0xD1, 0xB8, 0x78, 0x56, 0x34, 0x12,
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0xF8, 0x7F, 0x00, 0x00};
    SC_REQUIRE(std::equal(expected.begin(), expected.end(), slot.begin()));
}

SC_TEST_CASE("write_indirect_stub rejects a buffer smaller than the stub") {
    std::array<std::uint8_t, syscall::kIndirectStubSize - 1> slot{};
    SC_REQUIRE(!syscall::write_indirect_stub(slot, kSampleSsn, kSampleGadget));
}

SC_TEST_CASE("write_indirect_stub keeps stubs inside their stride") {
    std::array<std::uint8_t, syscall::kTrampolineStride * 2> region{};
    auto slots = std::span<std::uint8_t>(region);
    auto first = slots.first(syscall::kTrampolineStride);
    auto second = slots.subspan(syscall::kTrampolineStride, syscall::kTrampolineStride);

    SC_REQUIRE(syscall::write_indirect_stub(first, 1, 0x1000));
    const std::vector<std::uint8_t> first_copy(first.begin(), first.end());

    SC_REQUIRE(syscall::write_indirect_stub(second, 2, 0x2000));
    SC_REQUIRE(std::equal(first_copy.begin(), first_copy.end(), first.begin()));
}

namespace {

constexpr std::array<std::uint64_t, syscall::kSpoofFrameCount> kSampleFrames{
    0x00007FF8AABBCCDD,
    0x00007FF8AABBCCEE,
    0x00007FF8AABBCCFF};
constexpr std::uint64_t kSampleTerminator = 0x00007FF8AABBDD00;

syscall::SpoofAddresses sample_addresses() {
    syscall::SpoofAddresses addresses{};
    addresses.frames = kSampleFrames;
    addresses.terminator = kSampleTerminator;
    return addresses;
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
    return std::search(stub.begin(), stub.end(), pattern.begin(), pattern.end()) != stub.end();
}

std::vector<std::uint8_t> expected_arg_block() {
    std::vector<std::uint8_t> block;
    for (std::size_t index = 0; index < syscall::kSpoofArgCount; ++index) {
        const auto source = static_cast<std::uint32_t>(
            syscall::kSpoofArgSourceOffset + index * sizeof(std::uint64_t));
        const auto destination = static_cast<std::uint8_t>(
            syscall::kSpoofArgOffset + index * sizeof(std::uint64_t));
        const std::array<std::uint8_t, 4> load{0x48, 0x8B, 0x84, 0x24};
        const std::array<std::uint8_t, 4> store{0x48, 0x89, 0x44, 0x24};
        block.insert(block.end(), load.begin(), load.end());
        for (std::size_t byte = 0; byte < sizeof(source); ++byte) {
            block.push_back(static_cast<std::uint8_t>(source >> (byte * 8)));
        }
        block.insert(block.end(), store.begin(), store.end());
        block.push_back(destination);
    }
    return block;
}

}

SC_TEST_CASE("write_spoofed_stub emits the expected prologue") {
    std::array<std::uint8_t, syscall::kSpoofStubSize> stub{};
    SC_REQUIRE(
        syscall::write_spoofed_stub(stub, kSampleSsn, kSampleGadget, sample_addresses()));
    const std::array<std::uint8_t, 11> prologue{
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00};
    SC_REQUIRE(std::equal(prologue.begin(), prologue.end(), stub.begin()));
}

SC_TEST_CASE("write_spoofed_stub emits the expected syscall tail") {
    std::array<std::uint8_t, syscall::kSpoofStubSize> stub{};
    SC_REQUIRE(
        syscall::write_spoofed_stub(stub, kSampleSsn, kSampleGadget, sample_addresses()));
    const std::array<std::uint8_t, 22> tail{
        0x4C, 0x8B, 0xD1, 0xB8, 0x78, 0x56, 0x34, 0x12,
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0xF8, 0x7F, 0x00, 0x00};
    SC_REQUIRE(std::equal(tail.begin(), tail.end(), stub.end() - tail.size()));
}

SC_TEST_CASE("write_spoofed_stub embeds every fake frame address") {
    std::array<std::uint8_t, syscall::kSpoofStubSize> stub{};
    SC_REQUIRE(
        syscall::write_spoofed_stub(stub, kSampleSsn, kSampleGadget, sample_addresses()));
    for (const auto frame : kSampleFrames) {
        SC_REQUIRE(contains(stub, encode_u64(frame)));
    }
    SC_REQUIRE(contains(stub, encode_u64(kSampleTerminator)));
}

SC_TEST_CASE("write_spoofed_stub copies the caller stack arguments") {
    std::array<std::uint8_t, syscall::kSpoofStubSize> stub{};
    SC_REQUIRE(
        syscall::write_spoofed_stub(stub, kSampleSsn, kSampleGadget, sample_addresses()));
    SC_REQUIRE(contains(stub, expected_arg_block()));
}

SC_TEST_CASE("write_spoofed_stub rejects a buffer smaller than the stub") {
    std::array<std::uint8_t, syscall::kSpoofStubSize - 1> slot{};
    SC_REQUIRE(
        !syscall::write_spoofed_stub(slot, kSampleSsn, kSampleGadget, sample_addresses()));
}

SC_TEST_CASE("write_spoofed_stub keeps stubs inside their stride") {
    std::array<std::uint8_t, syscall::kTrampolineStride * 2> region{};
    auto slots = std::span<std::uint8_t>(region);
    auto first = slots.first(syscall::kTrampolineStride);
    auto second = slots.subspan(syscall::kTrampolineStride, syscall::kTrampolineStride);

    SC_REQUIRE(syscall::write_spoofed_stub(
        first, 1, 0x1000, sample_addresses()));
    const std::vector<std::uint8_t> first_copy(first.begin(), first.end());

    SC_REQUIRE(syscall::write_spoofed_stub(
        second, 2, 0x2000, sample_addresses()));
    SC_REQUIRE(std::equal(first_copy.begin(), first_copy.end(), first.begin()));
}

SC_TEST_CASE("write_spoofed_stub does not write past the stub") {
    std::array<std::uint8_t, syscall::kTrampolineStride> slot{};
    slot.fill(0xAA);
    SC_REQUIRE(
        syscall::write_spoofed_stub(slot, kSampleSsn, kSampleGadget, sample_addresses()));
    SC_REQUIRE_EQ(0xAA, slot[syscall::kSpoofStubSize]);
}
