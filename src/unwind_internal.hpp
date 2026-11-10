#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace syscall::unwind::detail {

inline constexpr std::uint8_t kVersionMask = 0x07;
inline constexpr std::uint8_t kUnwindVersion = 1;
inline constexpr std::uint8_t kChainedFlag = 0x20;
inline constexpr std::uint8_t kFrameRegisterMask = 0x0F;
inline constexpr std::uint8_t kFrameOffsetShift = 4;
inline constexpr std::uint8_t kRbpRegister = 5;
inline constexpr std::uint8_t kOperationMask = 0x0F;
inline constexpr std::uint8_t kOperationInfoShift = 4;
inline constexpr std::size_t kUnwindCodeSize = 2;

inline constexpr std::uint8_t kPushNonvol = 0;
inline constexpr std::uint8_t kAllocLarge = 1;
inline constexpr std::uint8_t kAllocSmall = 2;
inline constexpr std::uint8_t kSetFpreg = 3;
inline constexpr std::uint8_t kSaveNonvol = 4;
inline constexpr std::uint8_t kSaveNonvolFar = 5;
inline constexpr std::uint8_t kSaveXmm128 = 8;
inline constexpr std::uint8_t kSaveXmm128Far = 9;
inline constexpr std::uint8_t kPushMachframe = 10;

struct UnwindHeader {
    std::uint8_t version_flags;
    std::uint8_t prolog_size;
    std::uint8_t code_count;
    std::uint8_t frame_info;
};

static_assert(sizeof(UnwindHeader) == 4);

struct UnwindCode {
    std::uint8_t offset;
    std::uint8_t operation;
    std::uint8_t info;
};

inline std::optional<std::size_t> extra_slots(
    std::uint8_t operation,
    std::uint8_t info) {
    switch (operation) {
    case kPushNonvol:
    case kAllocSmall:
    case kSetFpreg:
        return 0;
    case kAllocLarge:
        if (info == 0) {
            return 1;
        }
        if (info == 1) {
            return 2;
        }
        return std::nullopt;
    case kSaveNonvol:
    case kSaveXmm128:
        return 1;
    case kSaveNonvolFar:
    case kSaveXmm128Far:
        return 2;
    case kPushMachframe:
        return info <= 1 ? std::optional<std::size_t>(0) : std::nullopt;
    default:
        // Unknown operations can hide operand slots, so the next code cannot be
        // located. Refusing is safer than guessing.
        return std::nullopt;
    }
}

inline std::optional<UnwindCode> read_unwind_code(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t unwind_info_rva,
    std::size_t slot) {
    const auto offset = static_cast<std::size_t>(unwind_info_rva) +
                        sizeof(UnwindHeader) + slot * kUnwindCodeSize;
    if (offset > size || size - offset < kUnwindCodeSize) {
        return std::nullopt;
    }
    const auto operation = image[offset + 1];
    return UnwindCode{
        image[offset],
        static_cast<std::uint8_t>(operation & kOperationMask),
        static_cast<std::uint8_t>(operation >> kOperationInfoShift)};
}

}
