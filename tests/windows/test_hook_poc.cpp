#include "test_harness.hpp"
#include "windows_image.hpp"

#include "syscall/engine.hpp"
#include "syscall/gadget_finder.hpp"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace {

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);

constexpr std::size_t kHookPatchSize = 12;
constexpr LONG kStatusAccessDenied = static_cast<LONG>(0xC0000022u);
constexpr std::size_t kPageSize = 0x1000;
constexpr std::uint8_t kFirstPattern = 0x5A;
constexpr std::uint8_t kLastPattern = 0xA5;
constexpr std::uint8_t kMovRaxPrefix = 0x48;
constexpr std::uint8_t kMovRaxOpcode = 0xB8;
constexpr std::uint8_t kJmpRaxOpcode = 0xFF;
constexpr std::uint8_t kJmpRaxModRm = 0xE0;
constexpr std::size_t kImmediateOffset = 2;
constexpr std::size_t kJumpOffset = 10;

volatile LONG g_hook_calls = 0;

LONG NTAPI blocked_allocate(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG) {
    InterlockedIncrement(&g_hook_calls);
    return kStatusAccessDenied;
}

std::array<std::uint8_t, kHookPatchSize> make_absolute_jump(const void* destination) {
    std::array<std::uint8_t, kHookPatchSize> patch{};
    patch[0] = kMovRaxPrefix;
    patch[1] = kMovRaxOpcode;
    const auto address = reinterpret_cast<std::uint64_t>(destination);
    std::memcpy(patch.data() + kImmediateOffset, &address, sizeof(address));
    patch[kJumpOffset] = kJmpRaxOpcode;
    patch[kJumpOffset + 1] = kJmpRaxModRm;
    return patch;
}

class InlineHook {
public:
    InlineHook(void* target, const void* replacement) : target_(target) {
        SC_REQUIRE(VirtualProtect(target_, kHookPatchSize, PAGE_EXECUTE_READWRITE,
                                  &original_protect_) != 0);
        std::memcpy(original_.data(), target_, kHookPatchSize);
        const auto patch = make_absolute_jump(replacement);
        std::memcpy(target_, patch.data(), kHookPatchSize);
        installed_ = true;
        DWORD ignored = 0;
        VirtualProtect(target_, kHookPatchSize, original_protect_, &ignored);
        FlushInstructionCache(GetCurrentProcess(), target_, kHookPatchSize);
    }

    ~InlineHook() {
        if (!installed_) {
            return;
        }
        DWORD old = 0;
        if (VirtualProtect(target_, kHookPatchSize, PAGE_EXECUTE_READWRITE, &old) != 0) {
            std::memcpy(target_, original_.data(), kHookPatchSize);
            DWORD ignored = 0;
            VirtualProtect(target_, kHookPatchSize, old, &ignored);
            FlushInstructionCache(GetCurrentProcess(), target_, kHookPatchSize);
        }
    }

    InlineHook(const InlineHook&) = delete;
    InlineHook& operator=(const InlineHook&) = delete;

private:
    void* target_ = nullptr;
    std::array<std::uint8_t, kHookPatchSize> original_{};
    DWORD original_protect_ = 0;
    bool installed_ = false;
};

void require_safe_gadget(const support::LiveImage& image, const void* function) {
    const auto sections = support::live_sections(image);
    SC_REQUIRE(sections.has_value());
    const auto gadget = syscall::find_syscall_gadget(
        std::span<const std::uint8_t>(image.bytes, image.size), *sections);
    SC_REQUIRE(gadget.has_value());
    const auto function_rva = static_cast<std::uint32_t>(
        static_cast<const std::uint8_t*>(function) - image.bytes);
    SC_REQUIRE(*gadget < function_rva || *gadget >= function_rva + kHookPatchSize);
}

}

SC_TEST_CASE("engine bypasses an inline hook on NtAllocateVirtualMemory") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    const auto allocate = engine.get<NtAllocateVirtualMemoryFn>("NtAllocateVirtualMemory");
    SC_REQUIRE(allocate != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    const auto ntdll = support::live_ntdll();
    SC_REQUIRE(ntdll.bytes != nullptr);
    const auto live_allocate = reinterpret_cast<NtAllocateVirtualMemoryFn>(
        reinterpret_cast<void*>(GetProcAddress(ntdll.module, "NtAllocateVirtualMemory")));
    SC_REQUIRE(live_allocate != nullptr);
    require_safe_gadget(ntdll, reinterpret_cast<const void*>(live_allocate));

    g_hook_calls = 0;
    InlineHook hook(reinterpret_cast<void*>(live_allocate),
                    reinterpret_cast<const void*>(&blocked_allocate));

    void* blocked_base = nullptr;
    SIZE_T blocked_size = kPageSize;
    const LONG blocked = live_allocate(GetCurrentProcess(), &blocked_base, 0, &blocked_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SC_REQUIRE_EQ(kStatusAccessDenied, blocked);
    SC_REQUIRE_EQ(1L, static_cast<long>(g_hook_calls));
    SC_REQUIRE(blocked_base == nullptr);

    void* base = nullptr;
    SIZE_T size = kPageSize;
    const LONG allocated = allocate(GetCurrentProcess(), &base, 0, &size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SC_REQUIRE_EQ(0L, allocated);
    SC_REQUIRE(base != nullptr);
    SC_REQUIRE_EQ(1L, static_cast<long>(g_hook_calls));

    auto* bytes = static_cast<volatile std::uint8_t*>(base);
    bytes[0] = kFirstPattern;
    bytes[kPageSize - 1] = kLastPattern;
    SC_REQUIRE_EQ(static_cast<unsigned>(kFirstPattern), static_cast<unsigned>(bytes[0]));
    SC_REQUIRE_EQ(static_cast<unsigned>(kLastPattern),
                  static_cast<unsigned>(bytes[kPageSize - 1]));

    SC_REQUIRE(VirtualFree(base, 0, MEM_RELEASE) != 0);
}
