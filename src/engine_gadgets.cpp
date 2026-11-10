#include "syscall/engine.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/mitigations.hpp"
#include "syscall/unwind.hpp"

#include <span>

namespace syscall {

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
