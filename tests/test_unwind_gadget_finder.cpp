#include "image_builder.hpp"
#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/pe_types.hpp"
#include "syscall/unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace {

constexpr std::uint8_t kNop = 0x90;
constexpr std::uint8_t kRet = 0xC3;
constexpr std::uint8_t kLeave = 0xC9;
constexpr std::uint8_t kPopRbp = 0x5D;
constexpr std::uint32_t kFunctionSize = 0x20;

struct FunctionSpec {
    std::uint32_t begin;
    std::uint32_t end;
    std::uint8_t prolog_size = 8;
    std::uint8_t frame_register = support::kRbp;
    std::uint8_t frame_offset = 0;
    std::vector<support::CodeSpec> codes = support::canonical_rbp_codes();
};

support::Layout build_gadget_image(
    const std::vector<std::uint8_t>& text,
    const std::vector<FunctionSpec>& specs) {
    std::vector<std::vector<std::uint8_t>> infos;
    std::vector<std::uint8_t> unwind_section;
    for (const auto& spec : specs) {
        const auto frame_info = static_cast<std::uint8_t>(
            spec.frame_register | static_cast<std::uint8_t>(spec.frame_offset << 4));
        auto info = support::make_unwind_info(
            1, spec.prolog_size, frame_info, spec.codes);
        unwind_section.insert(unwind_section.end(), info.begin(), info.end());
        infos.push_back(std::move(info));
    }

    support::ImageBuilder builder;
    builder.add_section({"text", support::kCodeSection, text});
    builder.add_section(
        {"pdata", support::kDataSection,
         std::vector<std::uint8_t>(specs.size() * support::kRuntimeFunctionSize, 0)});
    builder.add_section({"unwind", support::kDataSection, unwind_section});
    auto layout = builder.build();

    const auto text_rva = layout.section_rvas[0];
    const auto pdata_rva = layout.section_rvas[1];
    std::uint32_t unwind_rva = layout.section_rvas[2];
    for (std::size_t i = 0; i < specs.size(); ++i) {
        const syscall::unwind::RuntimeFunction function{
            text_rva + specs[i].begin,
            text_rva + specs[i].end,
            unwind_rva};
        std::memcpy(
            layout.bytes.data() + pdata_rva + i * support::kRuntimeFunctionSize,
            &function, sizeof(function));
        unwind_rva += static_cast<std::uint32_t>(infos[i].size());
    }
    SC_REQUIRE(support::patch_data_directory(
        layout.bytes, layout, syscall::pe::kExceptionDirectoryIndex,
        pdata_rva,
        static_cast<std::uint32_t>(specs.size() * support::kRuntimeFunctionSize)));
    return layout;
}

std::optional<syscall::UnwindSpoofGadgets> find_gadgets(
    const support::Layout& layout) {
    const auto sections =
        syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size());
    if (!sections.has_value()) {
        return std::nullopt;
    }
    const auto functions =
        syscall::unwind::read_runtime_functions(layout.bytes.data(), layout.bytes.size());
    if (!functions.has_value()) {
        return std::nullopt;
    }
    return syscall::find_unwind_spoof_gadgets(
        std::span<const std::uint8_t>(layout.bytes.data(), layout.bytes.size()),
        *sections, *functions);
}

std::vector<std::uint8_t> canonical_text() {
    std::vector<std::uint8_t> text(0xC0, kNop);
    text[0x00] = 0x0F;
    text[0x01] = 0x05;
    text[0x02] = kRet;
    text[0x20] = kLeave;
    text[0x21] = kRet;
    text[0x40] = kPopRbp;
    text[0x41] = kRet;
    text[0x60] = kPopRbp;
    text[0x61] = kRet;
    text[0x80] = kLeave;
    text[0x81] = kRet;
    text[0xA0] = kPopRbp;
    text[0xA1] = kRet;
    return text;
}

std::vector<FunctionSpec> canonical_specs() {
    std::vector<FunctionSpec> specs;
    for (std::uint32_t i = 0; i < 5; ++i) {
        const auto begin = 0x10 + i * kFunctionSize;
        specs.push_back({begin, begin + kFunctionSize});
    }
    return specs;
}

}

SC_TEST_CASE("find_unwind_spoof_gadgets selects five distinct frame gadgets") {
    const auto layout = build_gadget_image(canonical_text(), canonical_specs());
    const auto gadgets = find_gadgets(layout);
    SC_REQUIRE(gadgets.has_value());
    const auto text = layout.section_rvas[0];
    SC_REQUIRE_EQ(text, gadgets->syscall);
    SC_REQUIRE_EQ(text + 0x20, gadgets->frames[0]);
    SC_REQUIRE_EQ(text + 0x40, gadgets->frames[1]);
    SC_REQUIRE_EQ(text + 0x60, gadgets->frames[2]);
    SC_REQUIRE_EQ(text + 0x80, gadgets->frames[3]);
    SC_REQUIRE_EQ(text + 0xA0, gadgets->frames[4]);
}

SC_TEST_CASE("find_unwind_spoof_gadgets skips a covered syscall gadget") {
    auto text = canonical_text();
    text.resize(0x120, kNop);
    text[0x100] = 0x0F;
    text[0x101] = 0x05;
    text[0x102] = kRet;
    auto specs = canonical_specs();
    specs.insert(specs.begin(), {0x00, 0x10});
    const auto layout = build_gadget_image(text, specs);
    const auto gadgets = find_gadgets(layout);
    SC_REQUIRE(gadgets.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0] + 0x100, gadgets->syscall);
}

SC_TEST_CASE("find_unwind_spoof_gadgets rejects a covered syscall gadget") {
    auto specs = canonical_specs();
    specs.insert(specs.begin(), {0x00, 0x10});
    const auto layout = build_gadget_image(canonical_text(), specs);
    SC_REQUIRE(!find_gadgets(layout).has_value());
}

SC_TEST_CASE("find_unwind_spoof_gadgets rejects a missing leave gadget") {
    auto text = canonical_text();
    text[0x20] = kPopRbp;
    text[0x80] = kPopRbp;
    const auto layout = build_gadget_image(text, canonical_specs());
    SC_REQUIRE(!find_gadgets(layout).has_value());
}

SC_TEST_CASE("find_unwind_spoof_gadgets rejects too few chain gadgets") {
    auto text = canonical_text();
    text.resize(0x50, kNop);
    const std::vector<FunctionSpec> specs{{0x10, 0x30}, {0x30, 0x50}};
    const auto layout = build_gadget_image(text, specs);
    SC_REQUIRE(!find_gadgets(layout).has_value());
}

SC_TEST_CASE("find_unwind_spoof_gadgets ignores gadgets before the prolog") {
    auto text = canonical_text();
    text[0x12] = kLeave;
    text[0x13] = kRet;
    const auto layout = build_gadget_image(text, canonical_specs());
    const auto gadgets = find_gadgets(layout);
    SC_REQUIRE(gadgets.has_value());
    SC_REQUIRE_EQ(layout.section_rvas[0] + 0x20, gadgets->frames[0]);
}

SC_TEST_CASE("find_unwind_spoof_gadgets ignores non rbp frame functions") {
    auto text = canonical_text();
    text.resize(0xD0, kNop);
    text[0xC0] = kPopRbp;
    text[0xC1] = kRet;
    auto specs = canonical_specs();
    specs[0].frame_register = 0;
    specs.push_back({0xB0, 0xD0});
    const auto layout = build_gadget_image(text, specs);
    const auto gadgets = find_gadgets(layout);
    SC_REQUIRE(gadgets.has_value());
    const auto text_rva = layout.section_rvas[0];
    SC_REQUIRE_EQ(text_rva + 0x80, gadgets->frames[0]);
    SC_REQUIRE(gadgets->frames[1] != text_rva + 0x20);
    SC_REQUIRE(gadgets->frames[2] != text_rva + 0x20);
    SC_REQUIRE(gadgets->frames[3] != text_rva + 0x20);
    SC_REQUIRE(gadgets->frames[4] != text_rva + 0x20);
}
