#include "syscall/ssn_resolver.hpp"

#include "syscall/stub_layout.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>

namespace syscall {
namespace {

std::optional<std::size_t> find_export_index(
    const std::vector<pe::Export>& exports,
    std::string_view name) {
    const auto match = std::find_if(
        exports.begin(), exports.end(),
        [name](const pe::Export& entry) { return entry.name == name; });
    if (match == exports.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(exports.begin(), match));
}

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

std::optional<std::uint32_t> resolve_from_neighbor(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::size_t index,
    std::size_t step) {
    if (index >= step) {
        const auto previous = read_stub_ssn(image, exports[index - step].rva);
        if (previous.has_value()) {
            return *previous + static_cast<std::uint32_t>(step);
        }
    }
    if (index + step < exports.size()) {
        const auto next = read_stub_ssn(image, exports[index + step].rva);
        if (next.has_value()) {
            if (*next < step) {
                return std::nullopt;
            }
            return *next - static_cast<std::uint32_t>(step);
        }
    }
    return std::nullopt;
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
    const auto index = find_export_index(exports, name);
    if (!index.has_value()) {
        return std::nullopt;
    }

    const auto direct = read_stub_ssn(image, exports[*index].rva);
    if (direct.has_value()) {
        return direct;
    }

    for (std::size_t step = 1; step < exports.size(); ++step) {
        const auto ssn = resolve_from_neighbor(image, exports, *index, step);
        if (ssn.has_value()) {
            return ssn;
        }
    }
    return std::nullopt;
}

}
