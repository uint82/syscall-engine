#include "call_preceded_fixture.hpp"
#include "test_harness.hpp"

#include "syscall/call_preceded_finder.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/unwind.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

std::optional<syscall::CallPrecededGadgets> find_gadgets(
    const support::Layout& layout) {
    const auto sections = syscall::pe::read_sections(
        layout.bytes.data(), layout.bytes.size());
    if (!sections.has_value()) {
        return std::nullopt;
    }
    const auto functions = syscall::unwind::read_runtime_functions(
        layout.bytes.data(), layout.bytes.size());
    if (!functions.has_value()) {
        return std::nullopt;
    }
    return syscall::find_call_preceded_gadgets(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
        *sections, *functions);
}

std::optional<syscall::CallPrecededGadgets> find_gadgets(
    const support::CallPrecededFixture& fixture) {
    return find_gadgets(fixture.layout);
}

std::vector<support::CallFrameSpec> four_valid_frames() {
    return {
        {support::CallFrame::small, 0x20},
        {support::CallFrame::small, 0x28},
        {support::CallFrame::small, 0x30},
        {support::CallFrame::small, 0x38},
    };
}

std::vector<support::CallFrameSpec> with_decoy(
    support::CallFrame frame,
    support::CallTarget target) {
    auto specs = four_valid_frames();
    specs.insert(specs.begin(),
                 support::CallFrameSpec{frame, 0x18, target});
    return specs;
}

void expect_valid_frames(
    const support::CallPrecededFixture& fixture,
    const syscall::CallPrecededGadgets& gadgets,
    std::size_t first_function) {
    for (std::size_t index = 0; index < gadgets.frames.size(); ++index) {
        SC_REQUIRE_EQ(
            fixture.text_rva + fixture.function_begins[first_function + index] +
                support::kCallSize,
            gadgets.frames[index].site);
        SC_REQUIRE_EQ(static_cast<std::uint32_t>(0x20 + index * 8),
                      gadgets.frames[index].frame_size);
    }
}

}

SC_TEST_CASE("find_call_preceded_gadgets selects unwind-consistent frames") {
    const std::vector<support::CallFrameSpec> specs{
        {support::CallFrame::small, 0x18},
        {support::CallFrame::small, 0x20},
        {support::CallFrame::small, 0x28},
        {support::CallFrame::small, 0x30},
    };
    const auto fixture = support::build_call_preceded_image(specs);
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    SC_REQUIRE_EQ(fixture.text_rva, gadgets->syscall);
    for (std::size_t index = 0; index < specs.size(); ++index) {
        SC_REQUIRE_EQ(
            fixture.text_rva + fixture.function_begins[index] +
                support::kCallSize,
            gadgets->frames[index].site);
        SC_REQUIRE_EQ(specs[index].frame_size,
                      gadgets->frames[index].frame_size);
    }
}

SC_TEST_CASE("find_call_preceded_gadgets reads imm32 frame sizes") {
    const std::vector<support::CallFrameSpec> specs{
        {support::CallFrame::large, 0x18},
        {support::CallFrame::large, 0x20},
        {support::CallFrame::large, 0x28},
        {support::CallFrame::large, 0x30},
    };
    const auto fixture = support::build_call_preceded_image(specs);
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    for (std::size_t index = 0; index < specs.size(); ++index) {
        SC_REQUIRE_EQ(
            fixture.text_rva + fixture.function_begins[index] +
                support::kCallSize,
            gadgets->frames[index].site);
        SC_REQUIRE_EQ(specs[index].frame_size,
                      gadgets->frames[index].frame_size);
    }
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a push frame") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::push, support::CallTarget::leaf));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a negative add") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::negative, support::CallTarget::leaf));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a missing ret") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::no_ret, support::CallTarget::leaf));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a function without unwind info") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::missing, support::CallTarget::leaf));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a non-executable target") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::small, support::CallTarget::data));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a target inside a function") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::small, support::CallTarget::middle));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets rejects a target outside the image") {
    const auto fixture = support::build_call_preceded_image(
        with_decoy(support::CallFrame::small, support::CallTarget::outside));
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    expect_valid_frames(fixture, *gadgets, 1);
}

SC_TEST_CASE("find_call_preceded_gadgets keeps one site per function") {
    const std::vector<support::CallFrameSpec> specs{
        {support::CallFrame::small, 0x18, support::CallTarget::leaf, true},
        {support::CallFrame::small, 0x28},
        {support::CallFrame::small, 0x30},
        {support::CallFrame::small, 0x38},
    };
    const auto fixture = support::build_call_preceded_image(specs);
    const auto gadgets = find_gadgets(fixture);
    SC_REQUIRE(gadgets.has_value());
    const std::array<std::uint32_t, 4> sizes{0x18, 0x28, 0x30, 0x38};
    for (std::size_t index = 0; index < sizes.size(); ++index) {
        SC_REQUIRE_EQ(sizes[index], gadgets->frames[index].frame_size);
    }
    SC_REQUIRE_EQ(
        fixture.text_rva + fixture.function_begins[0] + support::kCallSize,
        gadgets->frames[0].site);
    SC_REQUIRE(gadgets->frames[0].site !=
               fixture.text_rva + fixture.function_begins[0] +
                   support::kSecondSiteOffset + support::kCallSize);
}

SC_TEST_CASE("find_call_preceded_gadgets returns nothing with three functions") {
    const std::vector<support::CallFrameSpec> specs{
        {support::CallFrame::small, 0x18, support::CallTarget::leaf, true},
        {support::CallFrame::small, 0x28},
        {support::CallFrame::small, 0x30},
    };
    const auto fixture = support::build_call_preceded_image(specs);
    SC_REQUIRE(!find_gadgets(fixture).has_value());
}

SC_TEST_CASE("find_call_preceded_gadgets returns nothing without a leaf syscall") {
    support::ImageBuilder builder;
    builder.add_section({"code", support::kCodeSection, {0x90, 0x90, 0x90}});
    builder.add_section(
        {"pdata", support::kDataSection,
         std::vector<std::uint8_t>(support::kRuntimeFunctionSize, 0)});
    const auto layout = builder.build();
    SC_REQUIRE(!find_gadgets(layout).has_value());
}
