#pragma once

#include <cstdint>
#include <string_view>

namespace syscall {

inline constexpr std::uint64_t kFnvOffsetBasis = 0xCBF29CE484222325ULL;
inline constexpr std::uint64_t kFnvPrime = 0x100000001B3ULL;

// Older than most EDR vendors, and it still walks past their string scanners.
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
