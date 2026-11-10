#include "syscall/engine.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/mitigations.hpp"
#include "syscall/unwind.hpp"

#include <array>
#include <span>

namespace syscall {
namespace {

constexpr std::array<std::uint8_t, 1> kReturnBytes{kReturnOpcode};

template <std::size_t N>
bool all_frames_match(
    std::span<const std::uint8_t> image,
    const std::array<std::uint32_t, N>& frames,
    std::span<const std::uint8_t> expected) {
    for (const auto rva : frames) {
        if (!matches_bytes_at(image, rva, expected)) {
            return false;
        }
    }
    return true;
}

}

bool Engine::prepare_syscall_gadget() {
    const auto sections = pe::read_sections(live_image_, live_size_);
    if (!sections.has_value()) {
        return false;
    }
    const auto gadget = find_syscall_gadget(
        std::span<const std::uint8_t>(live_image_, live_size_), *sections);
    if (!gadget.has_value()) {
        return false;
    }
    gadget_rva_ = *gadget;
    return true;
}

bool Engine::prepare_spoof_gadgets() {
    const auto sections = pe::read_sections(live_image_, live_size_);
    if (!sections.has_value()) {
        return false;
    }
    const auto gadgets = find_spoof_gadgets(
        std::span<const std::uint8_t>(live_image_, live_size_), *sections);
    if (!gadgets.has_value()) {
        return false;
    }
    spoof_gadgets_ = *gadgets;
    return true;
}

bool Engine::prepare_unwind_gadgets() {
    const auto sections = pe::read_sections(live_image_, live_size_);
    if (!sections.has_value()) {
        return false;
    }
    const auto functions = unwind::read_runtime_functions(live_image_, live_size_);
    if (!functions.has_value()) {
        return false;
    }
    const auto gadgets = find_unwind_spoof_gadgets(
        std::span<const std::uint8_t>(live_image_, live_size_), *sections, *functions);
    if (!gadgets.has_value()) {
        return false;
    }
    unwind_gadgets_ = *gadgets;
    gadget_rva_ = gadgets->syscall;
    return true;
}

bool Engine::gadgets_valid() const {
    if (mode_ == Mode::kDirect) {
        return true;
    }
    const auto image = std::span<const std::uint8_t>(live_image_, live_size_);
    if (!matches_bytes_at(image, gadget_rva_, kSyscallGadget)) {
        return false;
    }
    if (mode_ == Mode::kIndirect) {
        return true;
    }
    if (mode_ == Mode::kIndirectUnwindSpoofed) {
        return all_frames_match(image, unwind_gadgets_.frames, kReturnBytes);
    }
    return all_frames_match(image, spoof_gadgets_.frames, kReturnBytes) &&
           matches_bytes_at(image, spoof_gadgets_.terminator, kLeaveRetGadget);
}

Mode Engine::resolve_mode(Mode requested) {
    if (requested == Mode::kDirect || requested == Mode::kIndirect) {
        return requested;
    }
    if (is_user_shadow_stack_enabled()) {
        return Mode::kIndirect;
    }
    if (requested == Mode::kIndirectUnwindSpoofed && prepare_unwind_gadgets()) {
        return Mode::kIndirectUnwindSpoofed;
    }
    if (prepare_spoof_gadgets()) {
        return Mode::kIndirectSpoofed;
    }
    return Mode::kIndirect;
}

}
