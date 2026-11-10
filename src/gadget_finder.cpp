#include "syscall/gadget_finder.hpp"

#include <algorithm>
#include <array>

namespace syscall {
namespace {

constexpr std::uint32_t kSyscallReturnOffset = 2;

static_assert(kSyscallGadget[kSyscallReturnOffset] == 0xC3);

std::size_t section_span(
    std::span<const std::uint8_t> image,
    const pe::SectionHeader& section) {
    const auto start = static_cast<std::size_t>(section.virtual_address);
    if (start >= image.size()) {
        return 0;
    }
    const auto declared =
        section.virtual_size != 0 ? section.virtual_size : section.raw_size;
    // The declared size can exceed the mapped image; clamp it to the mapped range.
    return std::min(static_cast<std::size_t>(declared), image.size() - start);
}

template <typename Visitor>
void visit_pattern(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    std::span<const std::uint8_t> pattern,
    Visitor visit) {
    for (const auto& section : sections) {
        if ((section.characteristics & pe::kSectionExecute) == 0) {
            continue;
        }
        const auto length = section_span(image, section);
        if (length < pattern.size()) {
            continue;
        }
        const auto code = image.subspan(section.virtual_address, length);
        for (std::size_t offset = 0; offset + pattern.size() <= code.size(); ++offset) {
            if (!std::equal(pattern.begin(), pattern.end(), code.begin() + offset)) {
                continue;
            }
            const auto rva = section.virtual_address + static_cast<std::uint32_t>(offset);
            if (!visit(rva)) {
                return;
            }
        }
    }
}

std::optional<std::uint32_t> find_pattern(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    std::span<const std::uint8_t> pattern) {
    std::optional<std::uint32_t> match;
    visit_pattern(image, sections, pattern, [&match](std::uint32_t rva) {
        match = rva;
        return false;
    });
    return match;
}

bool is_leaf_at(
    std::span<const std::uint8_t> image,
    const std::vector<unwind::RuntimeFunction>& functions,
    std::uint32_t rva) {
    const auto index = unwind::find_runtime_function(functions, rva);
    if (!index.has_value()) {
        return false;
    }
    return unwind::is_leaf_function(image.data(), image.size(), functions[*index]);
}

std::optional<std::uint32_t> find_leaf_pattern(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    std::span<const std::uint8_t> pattern,
    const std::vector<unwind::RuntimeFunction>& functions) {
    std::optional<std::uint32_t> match;
    visit_pattern(image, sections, pattern, [&](std::uint32_t rva) {
        if (!is_leaf_at(image, functions, rva)) {
            return true;
        }
        match = rva;
        return false;
    });
    return match;
}

std::size_t collect_frame_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    SpoofGadgets& gadgets) {
    std::size_t count = 0;
    const std::array<std::uint8_t, 1> pattern{kReturnOpcode};
    visit_pattern(image, sections, pattern, [&](std::uint32_t rva) {
        gadgets.frames[count] = rva;
        ++count;
        return count < gadgets.frames.size();
    });
    return count;
}

bool is_used(
    const std::array<std::uint32_t, kUnwindGadgetCount>& frames,
    std::size_t count,
    std::uint32_t candidate) {
    return std::find(frames.begin(), frames.begin() + count, candidate) !=
           frames.begin() + count;
}

std::size_t collect_unwind_frames(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions,
    std::uint32_t syscall_rva,
    UnwindSpoofGadgets& gadgets) {
    std::size_t count = 0;
    const std::array<std::uint8_t, 1> pattern{kReturnOpcode};
    visit_pattern(image, sections, pattern, [&](std::uint32_t rva) {
        if (rva == syscall_rva + kSyscallReturnOffset) {
            return true;
        }
        if (!is_leaf_at(image, functions, rva)) {
            return true;
        }
        if (is_used(gadgets.frames, count, rva)) {
            return true;
        }
        gadgets.frames[count] = rva;
        ++count;
        return count < gadgets.frames.size();
    });
    return count;
}

}

bool matches_bytes_at(
    std::span<const std::uint8_t> image,
    std::uint32_t rva,
    std::span<const std::uint8_t> expected) {
    if (expected.empty()) {
        return false;
    }
    const auto start = static_cast<std::size_t>(rva);
    if (start > image.size() || expected.size() > image.size() - start) {
        return false;
    }
    return std::equal(expected.begin(), expected.end(), image.begin() + start);
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

std::optional<UnwindSpoofGadgets> find_unwind_spoof_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions) {
    const auto syscall = find_leaf_pattern(image, sections, kSyscallGadget, functions);
    if (!syscall.has_value()) {
        return std::nullopt;
    }
    UnwindSpoofGadgets result{};
    result.syscall = *syscall;
    if (collect_unwind_frames(image, sections, functions, *syscall, result) <
        result.frames.size()) {
        return std::nullopt;
    }
    return result;
}

}
