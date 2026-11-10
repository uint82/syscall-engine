#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "syscall/gadget_finder.hpp"
#include "syscall/pe_types.hpp"
#include "syscall/unwind.hpp"

namespace syscall {

struct CallPrecededFrame {
    std::uint32_t site = 0;
    std::uint32_t frame_size = 0;
};

struct CallPrecededGadgets {
    std::uint32_t syscall = 0;
    std::array<CallPrecededFrame, kUnwindGadgetCount> frames{};
};

std::optional<CallPrecededGadgets> find_call_preceded_gadgets(
    std::span<const std::uint8_t> image,
    const std::vector<pe::SectionHeader>& sections,
    const std::vector<unwind::RuntimeFunction>& functions);

}
