#include "test_harness.hpp"
#include "windows_image.hpp"

#include "syscall/engine.hpp"
#include "syscall/gadget_finder.hpp"
#include "syscall/pe_types.hpp"
#include "syscall/stub_layout.hpp"
#include "syscall/unwind.hpp"

#include <windows.h>

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

using NtQuerySystemTimeFn = LONG(NTAPI*)(LARGE_INTEGER*);

constexpr std::uint8_t kNop = 0x90;

struct LiveNtdll {
    support::LiveImage image;
    std::vector<syscall::pe::SectionHeader> sections;
};

LiveNtdll require_live_ntdll() {
    const auto image = support::live_ntdll();
    SC_REQUIRE(image.bytes != nullptr);
    const auto sections = support::live_sections(image);
    SC_REQUIRE(sections.has_value());
    return {image, std::move(*sections)};
}

std::span<const std::uint8_t> image_span(const support::LiveImage& image) {
    return std::span<const std::uint8_t>(image.bytes, image.size);
}

std::uint32_t require_syscall_gadget(const LiveNtdll& ntdll) {
    const auto gadget = syscall::find_syscall_gadget(image_span(ntdll.image), ntdll.sections);
    SC_REQUIRE(gadget.has_value());
    return *gadget;
}

syscall::SpoofGadgets require_spoof_gadgets(const LiveNtdll& ntdll) {
    const auto gadgets = syscall::find_spoof_gadgets(image_span(ntdll.image), ntdll.sections);
    SC_REQUIRE(gadgets.has_value());
    return *gadgets;
}

std::uint32_t require_non_syscall_frame(
    const LiveNtdll& ntdll, const syscall::SpoofGadgets& gadgets) {
    const auto syscall = require_syscall_gadget(ntdll);
    for (const auto frame : gadgets.frames) {
        if (frame != syscall + syscall::kSyscallInstructionLength) {
            return frame;
        }
    }
    SC_REQUIRE(false);
    return 0;
}

syscall::UnwindSpoofGadgets require_unwind_gadgets(const LiveNtdll& ntdll) {
    const auto functions = syscall::unwind::read_runtime_functions(
        ntdll.image.bytes, ntdll.image.size);
    SC_REQUIRE(functions.has_value());
    const auto gadgets = syscall::find_unwind_spoof_gadgets(
        image_span(ntdll.image), ntdll.sections, *functions);
    SC_REQUIRE(gadgets.has_value());
    return *gadgets;
}

std::uint8_t* at(const support::LiveImage& image, std::uint32_t rva) {
    return const_cast<std::uint8_t*>(image.bytes) + rva;
}

class BytePatch {
public:
    BytePatch(std::uint8_t* address, std::uint8_t replacement) : address_(address) {
        SC_REQUIRE(VirtualProtect(address_, sizeof(original_), PAGE_EXECUTE_READWRITE,
                                  &original_protect_) != 0);
        original_ = *address_;
        *address_ = replacement;
        restore_protection();
        FlushInstructionCache(GetCurrentProcess(), address_, sizeof(original_));
        installed_ = true;
    }

    ~BytePatch() {
        if (!installed_) {
            return;
        }
        DWORD ignored = 0;
        if (VirtualProtect(address_, sizeof(original_), PAGE_EXECUTE_READWRITE, &ignored) != 0) {
            *address_ = original_;
            restore_protection();
            FlushInstructionCache(GetCurrentProcess(), address_, sizeof(original_));
        }
    }

    BytePatch(const BytePatch&) = delete;
    BytePatch& operator=(const BytePatch&) = delete;

private:
    void restore_protection() {
        DWORD ignored = 0;
        VirtualProtect(address_, sizeof(original_), original_protect_, &ignored);
    }

    std::uint8_t* address_ = nullptr;
    std::uint8_t original_ = 0;
    DWORD original_protect_ = 0;
    bool installed_ = false;
};

void require_rejected_then_recovered(
    syscall::Engine& engine, const support::LiveImage& image, std::uint32_t rva) {
    {
        BytePatch patch(at(image, rva), kNop);
        SC_REQUIRE(engine.resolve("NtClose") == nullptr);
        SC_REQUIRE(engine.last_error() == syscall::Status::kGadgetInvalid);
    }
    SC_REQUIRE(engine.resolve("NtClose") != nullptr);
}

}

SC_TEST_CASE("resolve rejects a patched syscall gadget") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    const auto ntdll = require_live_ntdll();
    const auto gadget = require_syscall_gadget(ntdll);
    require_rejected_then_recovered(engine, ntdll.image, gadget);
}

SC_TEST_CASE("resolve rechecks a cached stub when the gadget changes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    void* first = engine.resolve("NtClose");
    SC_REQUIRE(first != nullptr);
    const auto ntdll = require_live_ntdll();
    const auto gadget = require_syscall_gadget(ntdll);
    require_rejected_then_recovered(engine, ntdll.image, gadget);
    SC_REQUIRE(engine.resolve("NtClose") == first);
}

SC_TEST_CASE("commit rejects a gadget patched after resolve") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    const auto ntdll = require_live_ntdll();
    const auto gadget = require_syscall_gadget(ntdll);
    {
        BytePatch patch(at(ntdll.image, gadget), kNop);
        SC_REQUIRE(engine.commit() == syscall::Status::kGadgetInvalid);
        SC_REQUIRE(engine.last_error() == syscall::Status::kGadgetInvalid);
    }
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);
    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("resolve rejects a patched spoof frame") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(engine.mode() == syscall::Mode::kIndirectSpoofed);
    const auto ntdll = require_live_ntdll();
    const auto gadgets = require_spoof_gadgets(ntdll);
    const auto frame = require_non_syscall_frame(ntdll, gadgets);
    require_rejected_then_recovered(engine, ntdll.image, frame);
}

SC_TEST_CASE("resolve rejects a patched spoof terminator") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(engine.mode() == syscall::Mode::kIndirectSpoofed);
    const auto ntdll = require_live_ntdll();
    const auto gadgets = require_spoof_gadgets(ntdll);
    require_rejected_then_recovered(engine, ntdll.image, gadgets.terminator);
}

SC_TEST_CASE("resolve rejects a patched unwind syscall gadget") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(engine.mode() == syscall::Mode::kIndirectUnwindSpoofed);
    const auto ntdll = require_live_ntdll();
    const auto gadgets = require_unwind_gadgets(ntdll);
    require_rejected_then_recovered(engine, ntdll.image, gadgets.syscall);
}

SC_TEST_CASE("resolve rejects a patched unwind frame") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(engine.mode() == syscall::Mode::kIndirectUnwindSpoofed);
    const auto ntdll = require_live_ntdll();
    const auto gadgets = require_unwind_gadgets(ntdll);
    require_rejected_then_recovered(engine, ntdll.image, gadgets.frames[0]);
}
