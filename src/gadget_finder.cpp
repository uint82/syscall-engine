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

}

std::optional<std::uint32_t> find_syscall_gadget(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections) {
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        const auto length = section_span(image, section);
        if (length < kSyscallGadget.size()) {
            continue;
        }
        const auto code = image.subspan(section.virtual_address, length);
        const auto match = std::search(
            code.begin(), code.end(), kSyscallGadget.begin(), kSyscallGadget.end());
        if (match == code.end()) {
            continue;
        }
        return section.virtual_address +
               static_cast<std::uint32_t>(std::distance(code.begin(), match));
    }
    return std::nullopt;
}

}
