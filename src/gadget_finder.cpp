#include "syscall/gadget_finder.hpp"

#include <algorithm>
#include <array>

namespace syscall {
namespace {

constexpr std::uint8_t kLeaveOpcode = 0xC9;
constexpr std::uint8_t kPopRbpOpcode = 0x5D;
constexpr std::size_t kGadgetSize = 2;

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

std::optional<std::uint32_t> find_leaf_pattern(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    std::span<const std::uint8_t> pattern,
    const std::vector<unwind::RuntimeFunction>& functions) {
    std::optional<std::uint32_t> match;
    visit_pattern(image, sections, pattern, [&](std::uint32_t rva) {
        if (unwind::find_runtime_function(functions, rva).has_value()) {
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

struct GadgetPool {
    std::optional<std::uint32_t> first_leave;
    std::vector<std::uint32_t> gadgets;
};

void collect_unwind_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<unwind::RuntimeFunction>& functions,
    GadgetPool& pool) {
    for (const auto& function : functions) {
        const auto prolog =
            unwind::read_rbp_prolog_size(image.data(), image.size(), function);
        if (!prolog.has_value()) {
            continue;
        }
        const auto begin = static_cast<std::size_t>(function.begin_rva) + *prolog;
        const auto end = static_cast<std::size_t>(function.end_rva);
        for (std::size_t offset = begin; offset + kGadgetSize <= end; ++offset) {
            if (image[offset + 1] != kReturnOpcode) {
                continue;
            }
            if (image[offset] == kLeaveOpcode) {
                if (!pool.first_leave.has_value()) {
                    pool.first_leave = static_cast<std::uint32_t>(offset);
                }
                pool.gadgets.push_back(static_cast<std::uint32_t>(offset));
            } else if (image[offset] == kPopRbpOpcode) {
                pool.gadgets.push_back(static_cast<std::uint32_t>(offset));
            }
        }
    }
}

bool is_used(
    const std::array<std::uint32_t, kUnwindGadgetCount>& frames,
    std::size_t count,
    std::uint32_t candidate) {
    return std::find(frames.begin(), frames.begin() + count, candidate) !=
           frames.begin() + count;
}

std::optional<UnwindSpoofGadgets> select_unwind_gadgets(
    std::uint32_t syscall_rva,
    const GadgetPool& pool) {
    if (!pool.first_leave.has_value()) {
        return std::nullopt;
    }
    UnwindSpoofGadgets result{};
    result.syscall = syscall_rva;
    result.frames[0] = *pool.first_leave;
    std::size_t count = 1;
    for (const auto candidate : pool.gadgets) {
        if (count == result.frames.size()) {
            break;
        }
        if (is_used(result.frames, count, candidate)) {
            continue;
        }
        result.frames[count] = candidate;
        ++count;
    }
    if (count < result.frames.size()) {
        return std::nullopt;
    }
    return result;
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

std::optional<UnwindSpoofGadgets> find_unwind_spoof_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions) {
    const auto syscall = find_leaf_pattern(image, sections, kSyscallGadget, functions);
    if (!syscall.has_value()) {
        return std::nullopt;
    }
    GadgetPool pool;
    collect_unwind_gadgets(image, functions, pool);
    return select_unwind_gadgets(*syscall, pool);
}

}
