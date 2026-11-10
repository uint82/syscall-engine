#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace syscall {

inline constexpr std::size_t kTrampolineStride = 256;

inline constexpr std::array<std::uint8_t, 4> kStubPrefix{0x4C, 0x8B, 0xD1, 0xB8};
inline constexpr std::uint8_t kSyscallOpcode0 = 0x0F;
inline constexpr std::uint8_t kSyscallOpcode1 = 0x05;
inline constexpr std::uint8_t kReturnOpcode = 0xC3;
inline constexpr std::uint8_t kJumpRipOpcode0 = 0xFF;
inline constexpr std::uint8_t kJumpRipOpcode1 = 0x25;
inline constexpr std::size_t kJumpRipLength = 6;
inline constexpr std::size_t kSyscallInstructionLength = 2;
inline constexpr std::size_t kReturnInstructionLength = 1;
inline constexpr std::size_t kDirectStubSize =
    kStubPrefix.size() + sizeof(std::uint32_t) + kSyscallInstructionLength +
    kReturnInstructionLength;
inline constexpr std::size_t kIndirectStubSize =
    kStubPrefix.size() + sizeof(std::uint32_t) + kJumpRipLength + sizeof(std::uint64_t);

inline constexpr std::uint8_t kPushRbpOpcode = 0x55;
inline constexpr std::array<std::uint8_t, 3> kMovRbpRspOpcode{0x48, 0x89, 0xE5};
inline constexpr std::array<std::uint8_t, 3> kSubRspOpcode{0x48, 0x81, 0xEC};
inline constexpr std::array<std::uint8_t, 2> kMovRaxImm64Opcode{0x48, 0xB8};
inline constexpr std::array<std::uint8_t, 4> kStoreRaxAtRspOpcode{0x48, 0x89, 0x04, 0x24};
inline constexpr std::array<std::uint8_t, 4> kStoreRaxAtRspDisp8Opcode{0x48, 0x89, 0x44, 0x24};
inline constexpr std::array<std::uint8_t, 4> kLoadRaxAtRspDisp32Opcode{0x48, 0x8B, 0x84, 0x24};

inline constexpr std::size_t kPushRbpLength = 1;
inline constexpr std::size_t kMovRbpRspLength = kMovRbpRspOpcode.size();
inline constexpr std::size_t kSubRspImm32Length =
    kSubRspOpcode.size() + sizeof(std::uint32_t);
inline constexpr std::size_t kMovRaxImm64Length =
    kMovRaxImm64Opcode.size() + sizeof(std::uint64_t);
inline constexpr std::size_t kStoreRaxAtRspLength = kStoreRaxAtRspOpcode.size();
inline constexpr std::size_t kStoreRaxAtRspDisp8Length =
    kStoreRaxAtRspDisp8Opcode.size() + sizeof(std::uint8_t);
inline constexpr std::size_t kLoadRaxAtRspDisp32Length =
    kLoadRaxAtRspDisp32Opcode.size() + sizeof(std::uint32_t);

inline constexpr std::size_t kUnwindFrameCount = 4;
inline constexpr std::size_t kUnwindGadgetCount = kUnwindFrameCount;
inline constexpr std::size_t kUnwindFrameSize =
    kUnwindFrameCount * sizeof(std::uint64_t);
inline constexpr std::size_t kUnwindArgCount = 8;
inline constexpr std::size_t kUnwindArgOffset = 0x28;
inline constexpr std::size_t kUnwindArgSourceOffset =
    kUnwindFrameSize + kUnwindArgOffset;

inline constexpr std::array<std::uint8_t, 4> kLoadR10AtRspDisp32Opcode{0x4C, 0x8B, 0x94, 0x24};
inline constexpr std::size_t kLoadR10AtRspDisp32Length =
    kLoadR10AtRspDisp32Opcode.size() + sizeof(std::uint32_t);
inline constexpr std::array<std::uint8_t, 4> kStoreR10AtRspDisp8Opcode{0x4C, 0x89, 0x54, 0x24};
inline constexpr std::size_t kStoreR10AtRspDisp8Length =
    kStoreR10AtRspDisp8Opcode.size() + sizeof(std::uint8_t);

inline constexpr std::size_t kSpoofFrameSize = 0x100;
inline constexpr std::size_t kSpoofFrameCount = 3;
inline constexpr std::size_t kSpoofSlotCount = kSpoofFrameCount + 1;
inline constexpr std::size_t kSpoofArgCount = 8;
inline constexpr std::size_t kSpoofArgOffset = 0x28;
inline constexpr std::size_t kSpoofArgSourceOffset =
    kSpoofFrameSize + sizeof(std::uint64_t) + kSpoofArgOffset;
inline constexpr std::size_t kSpoofStubSize =
    kPushRbpLength + kMovRbpRspLength + kSubRspImm32Length +
    kSpoofSlotCount * kMovRaxImm64Length + kStoreRaxAtRspLength +
    kSpoofFrameCount * kStoreRaxAtRspDisp8Length +
    kSpoofArgCount * (kLoadRaxAtRspDisp32Length + kStoreRaxAtRspDisp8Length) +
    kStubPrefix.size() + sizeof(std::uint32_t) + kJumpRipLength + sizeof(std::uint64_t);

inline constexpr std::array<std::uint8_t, 3> kSubRspImm8Opcode{0x48, 0x83, 0xEC};
inline constexpr std::size_t kSubRspImm8Length =
    kSubRspImm8Opcode.size() + sizeof(std::uint8_t);

inline constexpr std::size_t kUnwindStubSize =
    kSubRspImm8Length +
    kUnwindFrameCount * kMovRaxImm64Length +
    kStoreRaxAtRspLength +
    (kUnwindFrameCount - 1) * kStoreRaxAtRspDisp8Length +
    kUnwindArgCount * (kLoadR10AtRspDisp32Length + kStoreR10AtRspDisp8Length) +
    kStubPrefix.size() + sizeof(std::uint32_t) + kJumpRipLength + sizeof(std::uint64_t);

static_assert(kDirectStubSize <= kTrampolineStride);
static_assert(kIndirectStubSize <= kTrampolineStride);
static_assert(kSpoofStubSize <= kTrampolineStride);
static_assert(kUnwindStubSize <= kTrampolineStride);
static_assert(kSpoofArgOffset + kSpoofArgCount * sizeof(std::uint64_t) <= 0x80);
static_assert(kUnwindFrameSize <= 0x80);
static_assert(kUnwindFrameCount * sizeof(std::uint64_t) == kUnwindFrameSize);
static_assert(kUnwindArgOffset > kUnwindFrameSize);
static_assert(kUnwindArgOffset + kUnwindArgCount * sizeof(std::uint64_t) <= 0x80);
static_assert(kUnwindArgSourceOffset == kUnwindFrameSize + kUnwindArgOffset);

}
