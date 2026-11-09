#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace syscall {

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
inline constexpr std::size_t kTrampolineStride = 32;

}
