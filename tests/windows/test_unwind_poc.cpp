#include "test_harness.hpp"
#include "windows_image.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/unwind.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

constexpr std::size_t kFakeStackSize = syscall::kUnwindGadgetCount + 1;

void sentinel() {}

syscall::UnwindSpoofGadgets live_gadgets(const support::LiveImage& ntdll) {
    const auto sections = support::live_sections(ntdll);
    SC_REQUIRE(sections.has_value());
    const auto functions = syscall::unwind::read_runtime_functions(ntdll.bytes, ntdll.size);
    SC_REQUIRE(functions.has_value());
    const auto gadgets = syscall::find_unwind_spoof_gadgets(
        std::span<const std::uint8_t>(ntdll.bytes, ntdll.size), *sections, *functions);
    SC_REQUIRE(gadgets.has_value());
    return *gadgets;
}

}

SC_TEST_CASE("the leaf frame chain unwinds with RtlVirtualUnwind") {
    const auto ntdll = support::live_ntdll();
    SC_REQUIRE(ntdll.bytes != nullptr);
    const auto gadgets = live_gadgets(ntdll);
    const auto image_base = reinterpret_cast<DWORD64>(ntdll.bytes);

    alignas(16) std::array<DWORD64, kFakeStackSize> stack{};
    for (std::size_t i = 0; i < gadgets.frames.size(); ++i) {
        stack[i] = image_base + gadgets.frames[i];
    }
    stack.back() = reinterpret_cast<DWORD64>(&sentinel);

    CONTEXT context{};
    context.ContextFlags = CONTEXT_ALL;
    context.Rip = image_base + gadgets.syscall;
    context.Rsp = reinterpret_cast<DWORD64>(stack.data());

    std::array<DWORD64, kFakeStackSize> seen{};
    for (std::size_t i = 0; i < seen.size(); ++i) {
        DWORD64 function_image_base = 0;
        const auto entry = RtlLookupFunctionEntry(context.Rip, &function_image_base, nullptr);
        SC_REQUIRE(entry != nullptr);
        PVOID handler_data = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, function_image_base, context.Rip, entry, &context,
                         &handler_data, &establisher, nullptr);
        seen[i] = context.Rip;
    }

    for (std::size_t i = 0; i < gadgets.frames.size(); ++i) {
        SC_REQUIRE_EQ(image_base + gadgets.frames[i], seen[i]);
    }
    SC_REQUIRE_EQ(stack.back(), seen.back());
    SC_REQUIRE_EQ(reinterpret_cast<DWORD64>(stack.data() + stack.size()), context.Rsp);
}
