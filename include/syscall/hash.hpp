#pragma once

#include <cstdint>
#include <string_view>

namespace syscall {

inline constexpr std::uint64_t kFnvOffsetBasis = 0xCBF29CE484222325ULL;
inline constexpr std::uint64_t kFnvPrime = 0x100000001B3ULL;

// FNV-1a is small, constexpr, and dependency-free. It is not
// cryptographic. Optimized builds fold the hash and drop the name; unoptimized
// builds can keep the literal.
constexpr std::uint64_t fnv1a(std::string_view text) {
    std::uint64_t hash = kFnvOffsetBasis;
    for (const char value : text) {
        hash ^= static_cast<std::uint8_t>(value);
        hash *= kFnvPrime;
    }
    return hash;
}

}

#define SC_HASH(text) ::syscall::fnv1a(text)
