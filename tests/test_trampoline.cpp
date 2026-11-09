#include "test_harness.hpp"

#include "syscall/stub_layout.hpp"
#include "syscall/trampoline.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
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
