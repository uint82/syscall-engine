#include "syscall/unwind.hpp"

#include "pe_reader.hpp"
#include "unwind_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace syscall::unwind {

using namespace detail;

namespace {

inline constexpr std::size_t kRegisterSize = 8;
inline constexpr std::size_t kAllocUnit = 8;
inline constexpr std::size_t kAllocSmallBias = 8;
inline constexpr std::size_t kBitsPerByte = 8;

std::optional<std::uint32_t> read_operand(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t unwind_info_rva,
    std::size_t slot,
    std::size_t operand_size) {
    const auto offset = static_cast<std::size_t>(unwind_info_rva) +
                        sizeof(UnwindHeader) + slot * kUnwindCodeSize;
    if (offset > size || size - offset < operand_size) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < operand_size; ++index) {
        value |= static_cast<std::uint32_t>(image[offset + index])
                 << (index * kBitsPerByte);
    }
    return value;
}

bool apply_unwind_code(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t unwind_info_rva,
    std::size_t slot,
    const UnwindCode& code,
    FrameLayout& layout) {
    switch (code.operation) {
    case kPushNonvol:
        layout.frame_size += kRegisterSize;
        ++layout.push_count;
        return true;
    case kAllocLarge: {
        // info 0 stores the size in 8-byte units, info 1 stores the byte size.
        const auto operand_size =
            code.info == 0 ? sizeof(std::uint16_t) : sizeof(std::uint32_t);
        const auto operand =
            read_operand(image, size, unwind_info_rva, slot + 1, operand_size);
        if (!operand.has_value()) {
            return false;
        }
        const auto bytes =
            code.info == 0 ? static_cast<std::size_t>(*operand) * kAllocUnit
                           : static_cast<std::size_t>(*operand);
        layout.frame_size += bytes;
        layout.local_alloc += bytes;
        return true;
    }
    case kAllocSmall: {
        // The encoding is the size in 8-byte units minus the return address the
        // CPU already popped, so the bias puts that slot back.
        const auto bytes =
            static_cast<std::size_t>(code.info) * kAllocUnit + kAllocSmallBias;
        layout.frame_size += bytes;
        layout.local_alloc += bytes;
        return true;
    }
    case kSetFpreg:
    case kPushMachframe:
        return false;
    case kSaveNonvol:
    case kSaveNonvolFar:
    case kSaveXmm128:
    case kSaveXmm128Far:
        return true;
    default:
        return false;
    }
}

}

std::optional<FrameLayout> read_simple_frame_layout(
    const std::uint8_t* image,
    std::size_t size,
    const RuntimeFunction& function) {
    const auto header =
        pe::read_struct<UnwindHeader>(image, size, function.unwind_info_rva);
    if (!header.has_value()) {
        return std::nullopt;
    }
    if ((header->version_flags & kVersionMask) != kUnwindVersion ||
        (header->version_flags & kChainedFlag) != 0) {
        return std::nullopt;
    }
    // A frame pointer or chained record needs a value the fake stack cannot
    // supply, so a partial size is worse than no answer.
    if ((header->frame_info & kFrameRegisterMask) != 0 ||
        (header->frame_info >> kFrameOffsetShift) != 0) {
        return std::nullopt;
    }
    FrameLayout layout{};
    std::size_t slot = 0;
    while (slot < header->code_count) {
        const auto code =
            read_unwind_code(image, size, function.unwind_info_rva, slot);
        if (!code.has_value()) {
            return std::nullopt;
        }
        const auto extra = extra_slots(code->operation, code->info);
        if (!extra.has_value() || slot + 1 + *extra > header->code_count) {
            return std::nullopt;
        }
        if (!apply_unwind_code(image, size, function.unwind_info_rva, slot,
                               *code, layout)) {
            return std::nullopt;
        }
        slot += 1 + *extra;
    }
    return layout;
}

}
