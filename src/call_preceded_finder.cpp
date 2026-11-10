#include "syscall/call_preceded_finder.hpp"

#include "executable_sections.hpp"
#include "pe_reader.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_set>
#include <vector>

namespace syscall {
namespace {

// ntdll epilogs often look like `call __security_check_cookie; add rsp, N; ret`.
// A fake stack built from these sites keeps every return address inside a real
// function and matches the .pdata unwind codes for the site, so a validator
// that cross-checks return addresses against unwind info sees a consistent chain.
constexpr std::uint8_t kCallOpcode = 0xE8;
constexpr std::size_t kCallInstructionSize = 5;
constexpr std::uint8_t kRexW = 0x48;
constexpr std::uint8_t kAddImm8Opcode = 0x83;
constexpr std::uint8_t kAddImm32Opcode = 0x81;
constexpr std::uint8_t kAddRspModRm = 0xC4;
constexpr std::uint8_t kRetOpcode = 0xC3;
constexpr std::size_t kAddImm8Size = 4;
constexpr std::size_t kAddImm32Size = 7;
constexpr std::uint32_t kSignBit = 0x80000000;

struct AddRsp {
    std::uint32_t size = 0;
    std::size_t length = 0;
};

struct Candidate {
    std::uint32_t site = 0;
    std::uint32_t frame_size = 0;
    std::uint32_t function_begin = 0;
};

struct ScanContext {
    std::span<const std::uint8_t> image;
    const std::vector<pe::SectionHeader>& sections;
    const std::vector<unwind::RuntimeFunction>& functions;
};

struct SectionCursor {
    std::span<const std::uint8_t> code;
    std::uint32_t base = 0;
    std::size_t offset = 0;
};

SectionCursor cursor_at(const SectionCursor& cursor, std::size_t offset) {
    return {cursor.code, cursor.base, offset};
}

std::optional<AddRsp> read_add_rsp(const SectionCursor& cursor) {
    const auto& code = cursor.code;
    const auto offset = cursor.offset;
    if (offset > code.size() || code.size() - offset < kAddImm8Size) {
        return std::nullopt;
    }
    if (code[offset] != kRexW || code[offset + 2] != kAddRspModRm) {
        return std::nullopt;
    }
    if (code[offset + 1] == kAddImm8Opcode) {
        // A negative adjustment would move RSP into the return address slot.
        const auto value = static_cast<std::int8_t>(code[offset + 3]);
        if (value < 0) {
            return std::nullopt;
        }
        return AddRsp{static_cast<std::uint32_t>(value), kAddImm8Size};
    }
    if (code[offset + 1] != kAddImm32Opcode ||
        code.size() - offset < kAddImm32Size) {
        return std::nullopt;
    }
    const auto value = pe::read_struct<std::uint32_t>(
        code.data(), code.size(), offset + 3);
    if (!value.has_value() || (*value & kSignBit) != 0) {
        return std::nullopt;
    }
    return AddRsp{*value, kAddImm32Size};
}

std::optional<std::uint32_t> read_call_target(
    const SectionCursor& cursor,
    std::size_t image_size) {
    const auto& code = cursor.code;
    const auto offset = cursor.offset;
    if (offset > code.size() || code.size() - offset < kCallInstructionSize) {
        return std::nullopt;
    }
    if (code[offset] != kCallOpcode) {
        return std::nullopt;
    }
    const auto relative = pe::read_struct<std::int32_t>(
        code.data(), code.size(), offset + 1);
    if (!relative.has_value()) {
        return std::nullopt;
    }
    const auto call_rva = static_cast<std::uint64_t>(cursor.base) + offset;
    const auto target = static_cast<std::int64_t>(call_rva) +
                        static_cast<std::int64_t>(kCallInstructionSize) +
                        static_cast<std::int64_t>(*relative);
    if (target < 0 || target >= static_cast<std::int64_t>(image_size)) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(target);
}

std::optional<Candidate> read_candidate(
    const ScanContext& context,
    const SectionCursor& cursor) {
    // The scan is byte-level on purpose: a full disassembler would need to
    // separate code from embedded data, and the call opcode is rare enough
    // that false positives are cheap to reject.
    const auto target = read_call_target(cursor, context.image.size());
    if (!target.has_value() ||
        !detail::contains_executable_rva(context.sections, *target)) {
        return std::nullopt;
    }
    const auto target_index =
        unwind::find_runtime_function(context.functions, *target);
    if (!target_index.has_value() ||
        context.functions[*target_index].begin_rva != *target) {
        return std::nullopt;
    }
    const auto site_offset = cursor.offset + kCallInstructionSize;
    const auto add = read_add_rsp(cursor_at(cursor, site_offset));
    if (!add.has_value()) {
        return std::nullopt;
    }
    const auto ret_offset = site_offset + add->length;
    if (ret_offset >= cursor.code.size() ||
        cursor.code[ret_offset] != kRetOpcode) {
        return std::nullopt;
    }
    const auto site_rva =
        cursor.base + static_cast<std::uint32_t>(site_offset);
    const auto index =
        unwind::find_runtime_function(context.functions, site_rva);
    if (!index.has_value()) {
        return std::nullopt;
    }
    const auto layout = unwind::read_simple_frame_layout(
        context.image.data(), context.image.size(),
        context.functions[*index]);
    if (!layout.has_value() || layout->push_count != 0 ||
        layout->local_alloc != add->size || layout->frame_size != add->size) {
        return std::nullopt;
    }
    return Candidate{site_rva, static_cast<std::uint32_t>(layout->frame_size),
                     context.functions[*index].begin_rva};
}

std::vector<Candidate> collect_candidates(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions) {
    const ScanContext context{image, sections, functions};
    std::vector<Candidate> candidates;
    detail::visit_executable_sections(
        image, sections,
        [&](std::uint32_t base, std::span<const std::uint8_t> code) {
            for (std::size_t offset = 0; offset < code.size(); ++offset) {
                if (code[offset] != kCallOpcode) {
                    continue;
                }
                const auto candidate = read_candidate(
                    context, SectionCursor{code, base, offset});
                if (candidate.has_value()) {
                    candidates.push_back(*candidate);
                }
            }
            return true;
        });
    return candidates;
}

std::optional<CallPrecededGadgets> select_frames(
    std::vector<Candidate> candidates,
    std::uint32_t syscall) {
    // Small frames keep the fake stack compact. One site per function keeps
    // the chain from looking like a loop over the same epilog.
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& left, const Candidate& right) {
                  if (left.frame_size != right.frame_size) {
                      return left.frame_size < right.frame_size;
                  }
                  return left.site < right.site;
              });
    std::vector<Candidate> unique;
    unique.reserve(candidates.size());
    std::unordered_set<std::uint32_t> seen_functions;
    for (const auto& candidate : candidates) {
        if (seen_functions.insert(candidate.function_begin).second) {
            unique.push_back(candidate);
        }
    }
    if (unique.size() < kUnwindGadgetCount) {
        return std::nullopt;
    }
    CallPrecededGadgets result{};
    result.syscall = syscall;
    for (std::size_t index = 0; index < result.frames.size(); ++index) {
        result.frames[index] = {
            unique[index].site,
            unique[index].frame_size,
        };
    }
    return result;
}

}

std::optional<CallPrecededGadgets> find_call_preceded_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions) {
    const auto syscall = find_leaf_syscall_gadget(image, sections, functions);
    if (!syscall.has_value()) {
        return std::nullopt;
    }
    return select_frames(collect_candidates(image, sections, functions),
                         *syscall);
}

}
