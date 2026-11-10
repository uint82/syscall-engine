#pragma once

#include "image_builder.hpp"
#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/pe_image.hpp"
#include "syscall/unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace support {

enum class CallFrame {
    small,
    large,
    push,
    negative,
    no_ret,
    missing,
};

enum class CallTarget {
    leaf,
    middle,
    data,
    outside,
};

struct CallFrameSpec {
    CallFrame frame = CallFrame::small;
    std::uint32_t frame_size = 0x18;
    CallTarget target = CallTarget::leaf;
    bool second_site = false;
};

inline constexpr std::uint32_t kLeafSize = 0x10;
inline constexpr std::uint32_t kFunctionStride = 0x20;
inline constexpr std::size_t kSecondSiteOffset = 0x10;
inline constexpr std::uint8_t kCallOpcode = 0xE8;
inline constexpr std::uint8_t kRexW = 0x48;
inline constexpr std::uint8_t kAddImm8Opcode = 0x83;
inline constexpr std::uint8_t kAddImm32Opcode = 0x81;
inline constexpr std::uint8_t kAddRspModRm = 0xC4;
inline constexpr std::uint8_t kRetOpcode = 0xC3;
inline constexpr std::size_t kCallSize = 5;
inline constexpr std::size_t kAddImm8Size = 4;
inline constexpr std::size_t kAddImm32Size = 7;

struct CallPrecededFixture {
    Layout layout;
    std::uint32_t text_rva = 0;
    std::uint32_t pdata_rva = 0;
    std::uint32_t unwind_rva = 0;
    std::vector<std::uint32_t> function_begins;
};

inline std::uint8_t alloc_info(std::uint32_t frame_size) {
    return static_cast<std::uint8_t>((frame_size - 8) / 8);
}

inline std::size_t add_length(CallFrame frame) {
    return frame == CallFrame::large ? kAddImm32Size : kAddImm8Size;
}

inline std::vector<std::uint8_t> make_frame_unwind(
    const CallFrameSpec& spec) {
    switch (spec.frame) {
    case CallFrame::large:
        return make_alloc_large_unwind(
            1, spec.frame_size, static_cast<std::uint8_t>(kAddImm32Size));
    case CallFrame::push:
        return make_unwind_info(
            1, 6, 0,
            {{1, kPushNonvol, 3, 0},
             {2, kAllocSmall, alloc_info(spec.frame_size), 0}});
    default:
        return make_unwind_info(
            1, static_cast<std::uint8_t>(add_length(spec.frame)),
            0, {{static_cast<std::uint8_t>(add_length(spec.frame)),
                 kAllocSmall, alloc_info(spec.frame_size), 0}});
    }
}

inline void write_add(
    std::vector<std::uint8_t>& code,
    std::size_t offset,
    const CallFrameSpec& spec) {
    code[offset] = kRexW;
    if (spec.frame == CallFrame::large) {
        code[offset + 1] = kAddImm32Opcode;
        code[offset + 2] = kAddRspModRm;
        for (std::size_t index = 0; index < sizeof(std::uint32_t); ++index) {
            code[offset + 3 + index] = static_cast<std::uint8_t>(
                (spec.frame_size >> (index * 8)) & 0xFF);
        }
        return;
    }
    code[offset + 1] = kAddImm8Opcode;
    code[offset + 2] = kAddRspModRm;
    code[offset + 3] = spec.frame == CallFrame::negative
                           ? 0xF8
                           : static_cast<std::uint8_t>(spec.frame_size);
}

inline void write_epilog_body(
    std::vector<std::uint8_t>& code,
    std::size_t offset,
    const CallFrameSpec& spec) {
    write_add(code, offset + kCallSize, spec);
    if (spec.frame != CallFrame::no_ret) {
        code[offset + kCallSize + add_length(spec.frame)] = kRetOpcode;
    }
    if (!spec.second_site) {
        return;
    }
    const auto second = offset + kSecondSiteOffset;
    write_add(code, second + kCallSize, spec);
    if (spec.frame != CallFrame::no_ret) {
        code[second + kCallSize + add_length(spec.frame)] = kRetOpcode;
    }
}

inline void write_call(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint32_t call_rva,
    std::uint32_t target) {
    const auto relative = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(target - (call_rva + kCallSize)));
    const auto bits = static_cast<std::uint32_t>(relative);
    bytes[offset] = kCallOpcode;
    for (std::size_t index = 0; index < sizeof(bits); ++index) {
        bytes[offset + 1 + index] =
            static_cast<std::uint8_t>((bits >> (index * 8)) & 0xFF);
    }
}

inline std::uint32_t resolve_target(
    CallTarget target,
    std::uint32_t text,
    std::uint32_t pdata,
    std::size_t image_size) {
    switch (target) {
    case CallTarget::leaf:
        return text;
    case CallTarget::middle:
        return text + 2;
    case CallTarget::data:
        return pdata;
    case CallTarget::outside:
        return static_cast<std::uint32_t>(image_size) + 0x100;
    }
    return text;
}

inline CallPrecededFixture build_call_preceded_image(
    const std::vector<CallFrameSpec>& specs) {
    const auto text_size =
        kLeafSize + specs.size() * kFunctionStride + 0x10;
    std::vector<std::uint8_t> code(text_size, 0x90);
    code[0] = 0x0F;
    code[1] = 0x05;
    code[2] = kRetOpcode;

    std::vector<std::uint8_t> unwind_info;
    const auto leaf_info = make_unwind_info(1, 0, 0, {});
    unwind_info.insert(unwind_info.end(), leaf_info.begin(), leaf_info.end());

    std::vector<std::uint32_t> info_offsets(specs.size(), 0);
    std::vector<bool> has_unwind(specs.size(), true);
    std::size_t pdata_count = 1;
    for (std::size_t index = 0; index < specs.size(); ++index) {
        const auto begin =
            kLeafSize + static_cast<std::uint32_t>(index * kFunctionStride);
        write_epilog_body(code, begin, specs[index]);
        if (specs[index].frame == CallFrame::missing) {
            has_unwind[index] = false;
            continue;
        }
        info_offsets[index] = static_cast<std::uint32_t>(unwind_info.size());
        const auto info = make_frame_unwind(specs[index]);
        unwind_info.insert(unwind_info.end(), info.begin(), info.end());
        ++pdata_count;
    }

    ImageBuilder builder;
    builder.add_section({"text", kCodeSection, code});
    builder.add_section(
        {"pdata", kDataSection,
         std::vector<std::uint8_t>(pdata_count * kRuntimeFunctionSize, 0)});
    builder.add_section({"unwind", kDataSection, unwind_info});
    auto layout = builder.build();

    const auto text = layout.section_rvas[0];
    const auto pdata = layout.section_rvas[1];
    const auto unwind = layout.section_rvas[2];

    std::vector<std::uint32_t> function_begins;
    function_begins.reserve(specs.size());
    for (std::size_t index = 0; index < specs.size(); ++index) {
        const auto begin =
            kLeafSize + static_cast<std::uint32_t>(index * kFunctionStride);
        function_begins.push_back(begin);
        const auto target = resolve_target(
            specs[index].target, text, pdata, layout.bytes.size());
        write_call(layout.bytes, text + begin, text + begin, target);
        if (specs[index].second_site) {
            const auto second = begin + kSecondSiteOffset;
            write_call(layout.bytes, text + second, text + second, target);
        }
    }

    std::vector<syscall::unwind::RuntimeFunction> functions;
    functions.push_back({text, text + kLeafSize, unwind});
    for (std::size_t index = 0; index < specs.size(); ++index) {
        if (!has_unwind[index]) {
            continue;
        }
        const auto begin =
            text + kLeafSize + static_cast<std::uint32_t>(index * kFunctionStride);
        functions.push_back(
            {begin, begin + kFunctionStride, unwind + info_offsets[index]});
    }
    std::memcpy(layout.bytes.data() + pdata, functions.data(),
                functions.size() * sizeof(syscall::unwind::RuntimeFunction));
    SC_REQUIRE(patch_data_directory(
        layout.bytes, layout, syscall::pe::kExceptionDirectoryIndex, pdata,
        functions.size() * kRuntimeFunctionSize));
    return {std::move(layout), text, pdata, unwind, std::move(function_begins)};
}

}
