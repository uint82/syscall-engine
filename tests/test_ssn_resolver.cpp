#include "image_builder.hpp"
#include "test_harness.hpp"

#include "syscall/pe_image.hpp"
#include "syscall/ssn_resolver.hpp"
#include "syscall/stub_layout.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace {

std::optional<std::uint32_t> resolve_in(
    const support::Layout& layout,
    std::string_view name) {
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    if (!exports.has_value()) {
        return std::nullopt;
    }
    return syscall::resolve_ssn(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
        *exports, name);
}

std::optional<std::uint32_t> resolve_index_in(
    const support::Layout& layout,
    std::size_t index) {
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    if (!exports.has_value()) {
        return std::nullopt;
    }
    return syscall::resolve_ssn(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
        *exports, index);
}

}

SC_TEST_CASE("is_clean_stub accepts the canonical prologue") {
    const std::array<std::uint8_t, syscall::kDirectStubSize> stub{
        0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3};
    SC_REQUIRE(syscall::is_clean_stub(stub));
}

SC_TEST_CASE("is_clean_stub rejects a hooked prologue") {
    std::array<std::uint8_t, syscall::kDirectStubSize> stub{};
    stub.fill(0x90);
    stub[0] = 0xE9;
    SC_REQUIRE(!syscall::is_clean_stub(stub));
}

SC_TEST_CASE("is_clean_stub rejects a truncated buffer") {
    const std::array<std::uint8_t, 3> stub{0x4C, 0x8B, 0xD1};
    SC_REQUIRE(!syscall::is_clean_stub(stub));
}

SC_TEST_CASE("resolve_ssn reads a clean stub directly") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtDirect", 0x2A);
    const auto layout = builder.build();
    const auto ssn = resolve_in(layout, "NtDirect");
    SC_REQUIRE(ssn.has_value());
    SC_REQUIRE_EQ(std::uint32_t{0x2A}, *ssn);
}

SC_TEST_CASE("resolve_ssn recovers a hooked stub from its previous neighbor") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtFirst", 10);
    builder.add_hooked_export("NtHooked");
    builder.add_clean_export("NtLast", 12);
    const auto layout = builder.build();
    const auto ssn = resolve_in(layout, "NtHooked");
    SC_REQUIRE(ssn.has_value());
    SC_REQUIRE_EQ(std::uint32_t{11}, *ssn);
}

SC_TEST_CASE("resolve_ssn recovers a hooked stub from its next neighbor") {
    support::ImageBuilder builder;
    builder.add_hooked_export("NtHooked");
    builder.add_clean_export("NtClean", 20);
    const auto layout = builder.build();
    const auto ssn = resolve_in(layout, "NtHooked");
    SC_REQUIRE(ssn.has_value());
    SC_REQUIRE_EQ(std::uint32_t{19}, *ssn);
}

SC_TEST_CASE("resolve_ssn walks past consecutive hooked stubs") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtA", 30);
    builder.add_hooked_export("NtB");
    builder.add_hooked_export("NtC");
    builder.add_clean_export("NtD", 33);
    const auto layout = builder.build();

    const auto b = resolve_in(layout, "NtB");
    SC_REQUIRE(b.has_value());
    SC_REQUIRE_EQ(std::uint32_t{31}, *b);

    const auto c = resolve_in(layout, "NtC");
    SC_REQUIRE(c.has_value());
    SC_REQUIRE_EQ(std::uint32_t{32}, *c);
}

SC_TEST_CASE("resolve_ssn returns nothing for an unknown name") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtKnown", 5);
    const auto layout = builder.build();
    SC_REQUIRE(!resolve_in(layout, "NtUnknown").has_value());
}

SC_TEST_CASE("resolve_ssn rejects a stub outside the image") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtFar", 7);
    auto layout = builder.build();
    layout.bytes.resize(layout.stub_rvas[0]);

    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(!syscall::resolve_ssn(
                    std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
                    *exports, "NtFar")
                    .has_value());
}

SC_TEST_CASE("resolve_ssn rejects a truncated stub") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtShort", 7);
    auto layout = builder.build();
    layout.bytes.resize(layout.stub_rvas[0] + 5);

    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(!syscall::resolve_ssn(
                    std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
                    *exports, "NtShort")
                    .has_value());
}

SC_TEST_CASE("resolve_ssn rejects a neighbor ssn below the step distance") {
    support::ImageBuilder builder;
    builder.add_hooked_export("NtHooked");
    builder.add_clean_export("NtZero", 0);
    const auto layout = builder.build();
    SC_REQUIRE(!resolve_in(layout, "NtHooked").has_value());
}

SC_TEST_CASE("resolve_ssn by index reads a clean stub") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtDirect", 0x2A);
    const auto layout = builder.build();
    const auto ssn = resolve_index_in(layout, 0);
    SC_REQUIRE(ssn.has_value());
    SC_REQUIRE_EQ(std::uint32_t{0x2A}, *ssn);
}

SC_TEST_CASE("resolve_ssn by index recovers a hooked stub") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtFirst", 10);
    builder.add_hooked_export("NtHooked");
    builder.add_clean_export("NtLast", 12);
    const auto layout = builder.build();
    const auto ssn = resolve_index_in(layout, 1);
    SC_REQUIRE(ssn.has_value());
    SC_REQUIRE_EQ(std::uint32_t{11}, *ssn);
}

SC_TEST_CASE("resolve_ssn by index rejects an index outside the table") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtOnly", 1);
    const auto layout = builder.build();
    SC_REQUIRE(!resolve_index_in(layout, 1).has_value());
}
