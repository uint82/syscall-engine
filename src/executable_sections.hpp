#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "syscall/pe_types.hpp"

namespace syscall::detail {

inline std::uint32_t declared_size(const pe::SectionHeader& section) {
    // Some linkers leave virtual_size at zero for sections that are mapped
    // from the file, so fall back to the raw size in that case.
    return section.virtual_size != 0 ? section.virtual_size : section.raw_size;
}

inline bool contains_executable_rva(
    const std::vector<pe::SectionHeader>& sections,
    std::uint32_t rva) {
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        if (rva >= section.virtual_address &&
            rva - section.virtual_address < declared_size(section)) {
            return true;
        }
    }
    return false;
}

inline std::size_t section_span(
    std::span<const std::uint8_t> image,
    const pe::SectionHeader& section) {
    const auto start = static_cast<std::size_t>(section.virtual_address);
    if (start >= image.size()) {
        return 0;
    }
    // The declared size can exceed the mapped image; clamp it to the mapped range.
    return std::min(static_cast<std::size_t>(declared_size(section)),
                    image.size() - start);
}

template <typename Visitor>
void visit_executable_sections(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    Visitor visit) {
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        const auto length = section_span(image, section);
        if (length == 0) {
            continue;
        }
        if (!visit(section.virtual_address,
                   image.subspan(section.virtual_address, length))) {
            return;
        }
    }
}

}
