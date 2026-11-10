#pragma once

#include "image_builder.hpp"
#include "test_harness.hpp"

#include "syscall/pe_types.hpp"
#include "syscall/unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace support {

inline constexpr std::uint32_t kCodeSection = syscall::pe::kSectionExecute;
inline constexpr std::uint32_t kDataSection = 0x40000000;
inline constexpr std::size_t kRuntimeFunctionSize =
    sizeof(syscall::unwind::RuntimeFunction);
inline constexpr std::uint32_t kFunctionSize = 0x40;

inline constexpr std::uint8_t kPushNonvol = 0;
inline constexpr std::uint8_t kAllocLarge = 1;
inline constexpr std::uint8_t kAllocSmall = 2;
inline constexpr std::uint8_t kSetFpreg = 3;
inline constexpr std::uint8_t kSaveNonvol = 4;
inline constexpr std::uint8_t kSaveXmm128Far = 9;
inline constexpr std::uint8_t kPushMachframe = 10;
inline constexpr std::uint8_t kRbp = 5;

struct CodeSpec {
    std::uint8_t offset;
    std::uint8_t operation;
    std::uint8_t info;
    std::size_t extra_slots;
};

struct UnwindFixture {
    Layout layout;
    syscall::unwind::RuntimeFunction function;
};

inline std::vector<std::uint8_t> make_unwind_info(
    std::uint8_t version_flags,
    std::uint8_t prolog_size,
    std::uint8_t frame_info,
    const std::vector<CodeSpec>& codes) {
    std::vector<std::uint8_t> slots;
    for (const auto& code : codes) {
        slots.push_back(code.offset);
        slots.push_back(static_cast<std::uint8_t>((code.info << 4) | code.operation));
        slots.insert(slots.end(), code.extra_slots * 2, 0);
    }
    std::vector<std::uint8_t> info{
        version_flags,
        prolog_size,
        static_cast<std::uint8_t>(slots.size() / 2),
        frame_info};
    info.insert(info.end(), slots.begin(), slots.end());
    return info;
}

inline std::vector<std::uint8_t> make_alloc_large_unwind(
    std::uint8_t info,
    std::uint32_t size,
    std::uint8_t prolog_size = 4) {
    const auto operand_slots = info == 0 ? std::size_t{1} : std::size_t{2};
    std::vector<std::uint8_t> unwind{
        1,
        prolog_size,
        static_cast<std::uint8_t>(1 + operand_slots),
        0,
        prolog_size,
        static_cast<std::uint8_t>((info << 4) | kAllocLarge),
    };
    if (info == 0) {
        const auto units = static_cast<std::uint16_t>(size / 8);
        unwind.push_back(static_cast<std::uint8_t>(units & 0xFF));
        unwind.push_back(static_cast<std::uint8_t>((units >> 8) & 0xFF));
        return unwind;
    }
    for (std::size_t index = 0; index < 4; ++index) {
        unwind.push_back(
            static_cast<std::uint8_t>((size >> (index * 8)) & 0xFF));
    }
    return unwind;
}

inline std::vector<CodeSpec> canonical_rbp_codes() {
    return {
        {4, kAllocSmall, 3, 0},
        {1, kSetFpreg, 0, 0},
        {0, kPushNonvol, kRbp, 0},
    };
}

inline std::vector<std::uint8_t> canonical_rbp_unwind() {
    return make_unwind_info(1, 8, kRbp, canonical_rbp_codes());
}

inline UnwindFixture build_single_function_image(
    const std::vector<std::uint8_t>& unwind_info) {
    ImageBuilder builder;
    builder.add_section(
        {"text", kCodeSection, std::vector<std::uint8_t>(kFunctionSize, 0x90)});
    builder.add_section(
        {"pdata", kDataSection, std::vector<std::uint8_t>(kRuntimeFunctionSize, 0)});
    builder.add_section({"unwind", kDataSection, unwind_info});
    auto layout = builder.build();

    const syscall::unwind::RuntimeFunction function{
        layout.section_rvas[0],
        layout.section_rvas[0] + kFunctionSize,
        layout.section_rvas[2]};
    std::memcpy(layout.bytes.data() + layout.section_rvas[1], &function,
                sizeof(function));
    SC_REQUIRE(patch_data_directory(
        layout.bytes, layout, syscall::pe::kExceptionDirectoryIndex,
        layout.section_rvas[1], kRuntimeFunctionSize));
    return {std::move(layout), function};
}

inline Layout build_two_function_image(bool overlapping) {
    ImageBuilder builder;
    builder.add_section(
        {"text", kCodeSection, std::vector<std::uint8_t>(kFunctionSize, 0x90)});
    builder.add_section(
        {"pdata", kDataSection, std::vector<std::uint8_t>(2 * kRuntimeFunctionSize, 0)});
    builder.add_section({"unwind", kDataSection, canonical_rbp_unwind()});
    auto layout = builder.build();

    const auto text = layout.section_rvas[0];
    const auto pdata = layout.section_rvas[1];
    const auto unwind = layout.section_rvas[2];
    const auto second_begin = overlapping ? text + 0x10 : text + 0x20;
    const syscall::unwind::RuntimeFunction first{text, text + 0x20, unwind};
    const syscall::unwind::RuntimeFunction second{second_begin, text + 0x40, unwind};
    std::memcpy(layout.bytes.data() + pdata, &first, sizeof(first));
    std::memcpy(layout.bytes.data() + pdata + kRuntimeFunctionSize, &second,
                sizeof(second));
    SC_REQUIRE(patch_data_directory(
        layout.bytes, layout, syscall::pe::kExceptionDirectoryIndex, pdata,
        2 * kRuntimeFunctionSize));
    return layout;
}

inline void patch_runtime_function(
    Layout& layout,
    const syscall::unwind::RuntimeFunction& function) {
    std::memcpy(layout.bytes.data() + layout.section_rvas[1], &function,
                sizeof(function));
}

}
