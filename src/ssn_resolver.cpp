#include "syscall/ssn_resolver.hpp"

#include "syscall/stub_layout.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace syscall {
namespace {

std::optional<std::uint32_t> read_stub_ssn(
    std::span<const std::uint8_t> image,
    std::uint32_t rva) {
    if (rva > image.size() || image.size() - rva < kDirectStubSize) {
        return std::nullopt;
    }
    const auto stub = image.subspan(rva, kDirectStubSize);
    if (!is_clean_stub(stub)) {
        return std::nullopt;
    }
    std::uint32_t ssn = 0;
    std::memcpy(&ssn, stub.data() + kStubPrefix.size(), sizeof(ssn));
    return ssn;
}

enum class Direction {
    kPrevious,
    kNext,
};

struct CleanNeighbor {
    std::uint32_t ssn;
    std::uint32_t distance;
};

constexpr std::ptrdiff_t kPreviousStep = -1;
constexpr std::ptrdiff_t kNextStep = 1;

std::optional<CleanNeighbor> find_clean_neighbor(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::size_t index,
    Direction direction) {
    std::ptrdiff_t cursor = static_cast<std::ptrdiff_t>(index);
    const std::ptrdiff_t step =
        direction == Direction::kPrevious ? kPreviousStep : kNextStep;
    std::uint32_t distance = 0;
    std::uint32_t rva = exports[index].rva;
    for (std::size_t visited = 0; visited < exports.size(); ++visited) {
        cursor += step;
        if (cursor < 0 || static_cast<std::size_t>(cursor) >= exports.size()) {
            return std::nullopt;
        }
        const auto& candidate = exports[static_cast<std::size_t>(cursor)];
        // Nt and Zw aliases share one code address and one syscall number.
        if (candidate.rva == rva) {
            continue;
        }
        rva = candidate.rva;
        ++distance;
        const auto ssn = read_stub_ssn(image, candidate.rva);
        if (ssn.has_value()) {
            return CleanNeighbor{*ssn, distance};
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> estimate_ssn(
    const std::optional<CleanNeighbor>& neighbor,
    Direction direction) {
    if (!neighbor.has_value()) {
        return std::nullopt;
    }
    if (direction == Direction::kPrevious) {
        const auto headroom =
            std::numeric_limits<std::uint32_t>::max() - neighbor->ssn;
        if (neighbor->distance > headroom) {
            return std::nullopt;
        }
        return neighbor->ssn + neighbor->distance;
    }
    if (neighbor->ssn < neighbor->distance) {
        return std::nullopt;
    }
    return neighbor->ssn - neighbor->distance;
}

// Both sides must agree: an interleaved non-syscall export can shift one
// side's count, and either answer would ring the wrong kernel door.
std::optional<std::uint32_t> reconcile_estimates(
    const std::optional<std::uint32_t>& from_previous,
    const std::optional<std::uint32_t>& from_next) {
    if (from_previous.has_value() && from_next.has_value() &&
        *from_previous != *from_next) {
        return std::nullopt;
    }
    if (from_previous.has_value()) {
        return from_previous;
    }
    return from_next;
}

}

bool is_clean_stub(std::span<const std::uint8_t> code) {
    return code.size() >= kStubPrefix.size() &&
           std::equal(kStubPrefix.begin(), kStubPrefix.end(), code.begin());
}

std::optional<std::uint32_t> resolve_ssn(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::string_view name) {
    const auto index = pe::find_export(exports, name);
    if (!index.has_value()) {
        return std::nullopt;
    }
    return resolve_ssn(image, exports, *index);
}

std::optional<std::uint32_t> resolve_ssn(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::size_t index) {
    if (index >= exports.size()) {
        return std::nullopt;
    }

    const auto direct = read_stub_ssn(image, exports[index].rva);
    if (direct.has_value()) {
        return direct;
    }

    const auto previous =
        find_clean_neighbor(image, exports, index, Direction::kPrevious);
    const auto next = find_clean_neighbor(image, exports, index, Direction::kNext);
    return reconcile_estimates(
        estimate_ssn(previous, Direction::kPrevious),
        estimate_ssn(next, Direction::kNext));
}

}
