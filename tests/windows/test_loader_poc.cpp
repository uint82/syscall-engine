#include "test_harness.hpp"

#include "syscall/engine.hpp"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace {

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);
using NtWriteVirtualMemoryFn = LONG(NTAPI*)(HANDLE, void*, const void*, SIZE_T, SIZE_T*);
using NtProtectVirtualMemoryFn = LONG(NTAPI*)(HANDLE, void**, SIZE_T*, ULONG, ULONG*);
using NtCreateThreadExFn = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*, void*, ULONG,
                                        SIZE_T, SIZE_T, SIZE_T, void*);
using NtWaitForSingleObjectFn = LONG(NTAPI*)(HANDLE, BOOLEAN, void*);
using NtFreeVirtualMemoryFn = LONG(NTAPI*)(HANDLE, void**, SIZE_T*, ULONG);
using NtCloseFn = LONG(NTAPI*)(HANDLE);

constexpr std::size_t kPageSize = 0x1000;
constexpr LONG kPayloadMagic = 0x5A5A1234;
constexpr std::size_t kPayloadSize = 19;
constexpr std::size_t kAddressOffset = 2;
constexpr std::size_t kMagicOffset = 10;
constexpr std::size_t kXorOffset = 16;
constexpr std::size_t kRetOffset = 18;
constexpr std::uint8_t kMovRaxPrefix = 0x48;
constexpr std::uint8_t kMovRaxOpcode = 0xB8;
constexpr std::uint8_t kMovDwordPtrRaxOpcode = 0xC7;
constexpr std::uint8_t kMovDwordPtrRaxModRm = 0x00;
constexpr std::uint8_t kXorEaxOpcode = 0x31;
constexpr std::uint8_t kXorEaxModRm = 0xC0;
constexpr std::uint8_t kRetOpcode = 0xC3;

volatile LONG g_payload_magic = 0;

std::array<std::uint8_t, kPayloadSize> make_payload() {
    std::array<std::uint8_t, kPayloadSize> code{};
    code[0] = kMovRaxPrefix;
    code[1] = kMovRaxOpcode;
    const auto target = reinterpret_cast<std::uint64_t>(const_cast<LONG*>(&g_payload_magic));
    std::memcpy(code.data() + kAddressOffset, &target, sizeof(target));
    code[kMagicOffset] = kMovDwordPtrRaxOpcode;
    code[kMagicOffset + 1] = kMovDwordPtrRaxModRm;
    const auto magic = static_cast<std::uint32_t>(kPayloadMagic);
    std::memcpy(code.data() + kMagicOffset + 2, &magic, sizeof(magic));
    code[kXorOffset] = kXorEaxOpcode;
    code[kXorOffset + 1] = kXorEaxModRm;
    code[kRetOffset] = kRetOpcode;
    return code;
}

}

SC_TEST_CASE("the engine runs a benign payload through a full syscall loader") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    const auto allocate = engine.get<NtAllocateVirtualMemoryFn>("NtAllocateVirtualMemory");
    const auto write = engine.get<NtWriteVirtualMemoryFn>("NtWriteVirtualMemory");
    const auto protect = engine.get<NtProtectVirtualMemoryFn>("NtProtectVirtualMemory");
    const auto create_thread = engine.get<NtCreateThreadExFn>("NtCreateThreadEx");
    const auto wait = engine.get<NtWaitForSingleObjectFn>("NtWaitForSingleObject");
    const auto free_memory = engine.get<NtFreeVirtualMemoryFn>("NtFreeVirtualMemory");
    const auto close = engine.get<NtCloseFn>("NtClose");
    SC_REQUIRE(allocate != nullptr);
    SC_REQUIRE(write != nullptr);
    SC_REQUIRE(protect != nullptr);
    SC_REQUIRE(create_thread != nullptr);
    SC_REQUIRE(wait != nullptr);
    SC_REQUIRE(free_memory != nullptr);
    SC_REQUIRE(close != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    g_payload_magic = 0;

    void* base = nullptr;
    SIZE_T size = kPageSize;
    SC_REQUIRE_EQ(0L, allocate(GetCurrentProcess(), &base, 0, &size,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    SC_REQUIRE(base != nullptr);

    const auto code = make_payload();
    SIZE_T written = 0;
    SC_REQUIRE_EQ(0L, write(GetCurrentProcess(), base, code.data(), code.size(), &written));
    SC_REQUIRE_EQ(static_cast<SIZE_T>(code.size()), written);

    void* protect_base = base;
    SIZE_T protect_size = size;
    ULONG old_protect = 0;
    SC_REQUIRE_EQ(0L, protect(GetCurrentProcess(), &protect_base, &protect_size,
                              PAGE_EXECUTE_READ, &old_protect));

    HANDLE thread = nullptr;
    SC_REQUIRE_EQ(0L, create_thread(&thread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
                                    base, nullptr, 0, 0, 0, 0, nullptr));
    SC_REQUIRE(thread != nullptr);

    SC_REQUIRE_EQ(0L, wait(thread, FALSE, nullptr));
    SC_REQUIRE_EQ(kPayloadMagic, static_cast<LONG>(g_payload_magic));

    SC_REQUIRE_EQ(0L, close(thread));

    void* free_base = base;
    SIZE_T free_size = 0;
    SC_REQUIRE_EQ(0L, free_memory(GetCurrentProcess(), &free_base, &free_size, MEM_RELEASE));
}
