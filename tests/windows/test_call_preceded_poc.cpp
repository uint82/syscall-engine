#include "test_harness.hpp"
#include "windows_image.hpp"

#include "syscall/call_preceded_finder.hpp"
#include "syscall/unwind.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

void sentinel() {}

using Frames =
    std::array<syscall::CallPrecededFrame, syscall::kUnwindGadgetCount>;

std::size_t frame_offset(const Frames& frames, std::size_t index) {
    std::size_t offset = 0;
    for (std::size_t current = 0; current < index; ++current) {
        offset += sizeof(std::uint64_t) + frames[current].frame_size;
    }
    return offset;
}

std::size_t stack_slots(const Frames& frames) {
    return frame_offset(frames, frames.size()) / sizeof(std::uint64_t) + 1;
}

}

SC_TEST_CASE("the call-preceded frame chain unwinds with RtlVirtualUnwind") {
    const auto ntdll = support::live_ntdll();
    SC_REQUIRE(ntdll.bytes != nullptr);
    const auto sections = support::live_sections(ntdll);
    SC_REQUIRE(sections.has_value());
    const auto functions =
        syscall::unwind::read_runtime_functions(ntdll.bytes, ntdll.size);
    SC_REQUIRE(functions.has_value());
    const auto gadgets = syscall::find_call_preceded_gadgets(
        std::span<const std::uint8_t>(ntdll.bytes, ntdll.size), *sections,
        *functions);
    SC_REQUIRE(gadgets.has_value());

    const auto image_base = reinterpret_cast<DWORD64>(ntdll.bytes);
    std::vector<DWORD64> stack(stack_slots(gadgets->frames), 0);
    for (std::size_t index = 0; index < gadgets->frames.size(); ++index) {
        stack[frame_offset(gadgets->frames, index) / sizeof(DWORD64)] =
            image_base + gadgets->frames[index].site;
    }
    stack.back() = reinterpret_cast<DWORD64>(&sentinel);

    CONTEXT context{};
    context.ContextFlags = CONTEXT_ALL;
    context.Rip = image_base + gadgets->syscall;
    context.Rsp = reinterpret_cast<DWORD64>(stack.data());

    std::array<DWORD64, syscall::kUnwindGadgetCount + 1> seen{};
    for (std::size_t index = 0; index < seen.size(); ++index) {
        DWORD64 function_image_base = 0;
        const auto entry =
            RtlLookupFunctionEntry(context.Rip, &function_image_base, nullptr);
        SC_REQUIRE(entry != nullptr);
        PVOID handler_data = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, function_image_base, context.Rip,
                         entry, &context, &handler_data, &establisher, nullptr);
        seen[index] = context.Rip;
    }

    for (std::size_t index = 0; index < gadgets->frames.size(); ++index) {
        SC_REQUIRE_EQ(image_base + gadgets->frames[index].site, seen[index]);
    }
    SC_REQUIRE_EQ(reinterpret_cast<DWORD64>(&sentinel), seen.back());
    SC_REQUIRE_EQ(reinterpret_cast<DWORD64>(stack.data() + stack.size()),
                  context.Rsp);
}
