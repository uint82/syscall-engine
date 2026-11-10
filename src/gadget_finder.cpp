#include "syscall/gadget_finder.hpp"

#include <algorithm>
#include <iterator>

namespace syscall {
namespace {

std::size_t section_span(
    std::span<const std::uint8_t> image,
    const pe::SectionHeader& section) {
    const auto start = static_cast<std::size_t>(section.virtual_address);
    if (start >= image.size()) {
        return 0;
    }
    const auto declared =
        section.virtual_size != 0 ? section.virtual_size : section.raw_size;
    // A section can promise more bytes than the image maps. Believe the map.
    return std::min(static_cast<std::size_t>(declared), image.size() - start);
}

std::optional<std::uint32_t> find_pattern(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    std::span<const std::uint8_t> pattern) {
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        const auto length = section_span(image, section);
        if (length < pattern.size()) {
            continue;
        }
        const auto code = image.subspan(section.virtual_address, length);
        const auto match = std::search(
            code.begin(), code.end(), pattern.begin(), pattern.end());
        if (match == code.end()) {
            continue;
        }
        return section.virtual_address +
               static_cast<std::uint32_t>(std::distance(code.begin(), match));
    }
    return std::nullopt;
}

std::size_t collect_frame_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    SpoofGadgets& gadgets) {
    std::size_t count = 0;
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        const auto length = section_span(image, section);
        if (length == 0) {
            continue;
        }
        const auto code = image.subspan(section.virtual_address, length);
        for (std::size_t offset = 0; offset < code.size(); ++offset) {
            if (count == gadgets.frames.size()) {
                return count;
            }
            if (code[offset] != kReturnOpcode) {
                continue;
            }
            gadgets.frames[count] =
                section.virtual_address + static_cast<std::uint32_t>(offset);
            ++count;
        }
    }
    return count;
}

}

std::optional<std::uint32_t> find_syscall_gadget(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections) {
    return find_pattern(image, sections, kSyscallGadget);
}

std::optional<SpoofGadgets> find_spoof_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections) {
    SpoofGadgets gadgets{};
    if (collect_frame_gadgets(image, sections, gadgets) < gadgets.frames.size()) {
        return std::nullopt;
    }
    const auto terminator = find_pattern(image, sections, kLeaveRetGadget);
    if (!terminator.has_value()) {
        return std::nullopt;
    }
    gadgets.terminator = *terminator;
    return gadgets;
}

}
