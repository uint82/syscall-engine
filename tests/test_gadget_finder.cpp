#include "image_builder.hpp"
#include "test_harness.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/pe_types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace {

constexpr std::uint32_t kExecutable = syscall::pe::kSectionExecute;
constexpr std::uint32_t kReadOnly = 0x40000000;

std::optional<std::uint32_t> find_in(const support::Layout& layout) {
    const auto sections = syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size());
    if (!sections.has_value()) {
        return std::nullopt;
    }
    return syscall::find_syscall_gadget(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()), *sections);
}

std::optional<syscall::SpoofGadgets> find_spoof_in(const support::Layout& layout) {
    const auto sections = syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size());
    if (!sections.has_value()) {
        return std::nullopt;
    }
    return syscall::find_spoof_gadgets(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()), *sections);
}

std::size_t section_table_offset(const support::Layout& layout) {
    return layout.nt_offset + sizeof(syscall::pe::NtHeaders64);
}

}

SC_TEST_CASE("matches_bytes_at accepts a pattern inside the image") {
    const std::array<std::uint8_t, 5> image{0x90, 0x0F, 0x05, 0xC3, 0x90};
    SC_REQUIRE(syscall::matches_bytes_at(image, 1, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at rejects a different byte") {
    const std::array<std::uint8_t, 5> image{0x90, 0x0F, 0x05, 0x90, 0x90};
    SC_REQUIRE(!syscall::matches_bytes_at(image, 1, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at rejects a pattern past the image end") {
    const std::array<std::uint8_t, 4> image{0x0F, 0x05, 0xC3, 0x90};
    SC_REQUIRE(!syscall::matches_bytes_at(image, 4, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at rejects an rva past the image end") {
    const std::array<std::uint8_t, 4> image{0x0F, 0x05, 0xC3, 0x90};
    SC_REQUIRE(!syscall::matches_bytes_at(image, 5, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at rejects a pattern that crosses the image end") {
    const std::array<std::uint8_t, 4> image{0x0F, 0x05, 0xC3, 0x90};
    SC_REQUIRE(!syscall::matches_bytes_at(image, 2, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at accepts a pattern ending at the image end") {
    const std::array<std::uint8_t, 3> image{0x0F, 0x05, 0xC3};
    SC_REQUIRE(syscall::matches_bytes_at(image, 0, syscall::kSyscallGadget));
}

SC_TEST_CASE("matches_bytes_at rejects an empty pattern") {
    const std::array<std::uint8_t, 1> image{0x90};
    SC_REQUIRE(!syscall::matches_bytes_at(
        image, 0, std::span<const std::uint8_t>{}));
}

SC_TEST_CASE("matches_bytes_at rejects a pattern in an empty image") {
    SC_REQUIRE(!syscall::matches_bytes_at(
        std::span<const std::uint8_t>{}, 0, syscall::kSyscallGadget));
}

SC_TEST_CASE("find_syscall_gadget locates the gadget in an executable section") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0x90, 0x0F, 0x05, 0xC3, 0x90}});
    const auto layout = builder.build();
    const auto gadget = find_in(layout);
    SC_REQUIRE(gadget.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0] + 1, *gadget);
}

SC_TEST_CASE("find_syscall_gadget ignores non executable sections") {
    support::ImageBuilder builder;
    builder.add_section({"data", kReadOnly, {0x0F, 0x05, 0xC3}});
    const auto layout = builder.build();
    SC_REQUIRE(!find_in(layout).has_value());
}

SC_TEST_CASE("find_syscall_gadget prefers the first executable section") {
    support::ImageBuilder builder;
    builder.add_section({"data", kReadOnly, {0x0F, 0x05, 0xC3}});
    builder.add_section({"code", kExecutable, {0x90, 0x0F, 0x05, 0xC3}});
    const auto layout = builder.build();
    const auto gadget = find_in(layout);
    SC_REQUIRE(gadget.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[1] + 1, *gadget);
}

SC_TEST_CASE("find_syscall_gadget returns nothing when the pattern is absent") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0x90, 0x90, 0x90}});
    const auto layout = builder.build();
    SC_REQUIRE(!find_in(layout).has_value());
}

SC_TEST_CASE("find_syscall_gadget skips a section outside the image") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0x0F, 0x05, 0xC3}});
    auto layout = builder.build();
    layout.bytes.resize(layout.section_rvas[0]);
    SC_REQUIRE(!find_in(layout).has_value());
}

SC_TEST_CASE("find_syscall_gadget clamps the declared section size") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0x90, 0x0F, 0x05, 0xC3}});
    auto layout = builder.build();

    const auto offset = section_table_offset(layout) +
                        offsetof(syscall::pe::SectionHeader, virtual_size);
    support::write_u32_at(layout.bytes, offset, 0xFFFFFF);

    const auto gadget = find_in(layout);
    SC_REQUIRE(gadget.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0] + 1, *gadget);
}

SC_TEST_CASE("find_spoof_gadgets collects ret frames and a leave ret terminator") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable,
                         {0x90, 0xC3, 0x90, 0xC3, 0x90, 0xC3, 0xC9, 0xC3}});
    const auto layout = builder.build();
    const auto gadgets = find_spoof_in(layout);
    SC_REQUIRE(gadgets.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0] + 1, gadgets->frames[0]);
    SC_REQUIRE_EQ(layout.section_rvas[0] + 3, gadgets->frames[1]);
    SC_REQUIRE_EQ(layout.section_rvas[0] + 5, gadgets->frames[2]);
    SC_REQUIRE_EQ(layout.section_rvas[0] + 6, gadgets->terminator);
}

SC_TEST_CASE("find_spoof_gadgets rejects a missing terminator") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0xC3, 0xC3, 0xC3, 0x90}});
    const auto layout = builder.build();
    SC_REQUIRE(!find_spoof_in(layout).has_value());
}

SC_TEST_CASE("find_spoof_gadgets rejects too few frame gadgets") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0xC3, 0x90, 0xC9, 0xC3}});
    const auto layout = builder.build();
    SC_REQUIRE(!find_spoof_in(layout).has_value());
}

SC_TEST_CASE("find_spoof_gadgets ignores non executable sections") {
    support::ImageBuilder builder;
    builder.add_section({"data", kReadOnly, {0xC3, 0xC3, 0xC3, 0xC9, 0xC3}});
    builder.add_section({"code", kExecutable, {0x90, 0x90}});
    const auto layout = builder.build();
    SC_REQUIRE(!find_spoof_in(layout).has_value());
}

SC_TEST_CASE("find_spoof_gadgets spans executable sections") {
    support::ImageBuilder builder;
    builder.add_section({"first", kExecutable, {0xC3, 0xC3}});
    builder.add_section({"second", kExecutable, {0xC3, 0xC9, 0xC3}});
    const auto layout = builder.build();
    const auto gadgets = find_spoof_in(layout);
    SC_REQUIRE(gadgets.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0], gadgets->frames[0]);
    SC_REQUIRE_EQ(layout.section_rvas[0] + 1, gadgets->frames[1]);
    SC_REQUIRE_EQ(layout.section_rvas[1], gadgets->frames[2]);
    SC_REQUIRE_EQ(layout.section_rvas[1] + 1, gadgets->terminator);
}

SC_TEST_CASE("find_spoof_gadgets skips sections outside the image") {
    support::ImageBuilder builder;
    builder.add_section({"code", kExecutable, {0xC3, 0xC3, 0xC3, 0xC9, 0xC3}});
    auto layout = builder.build();
    layout.bytes.resize(layout.section_rvas[0]);
    SC_REQUIRE(!find_spoof_in(layout).has_value());
}
