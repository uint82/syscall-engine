#include "syscall/engine.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace {

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, std::size_t, std::size_t*, unsigned long, unsigned long);
using NtWriteVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void*, const void*, std::size_t, std::size_t*);
using NtProtectVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, std::size_t*, unsigned long, unsigned long*);
using NtCreateThreadExFn =
    LONG(NTAPI*)(HANDLE*, unsigned long, void*, HANDLE, void*, void*, unsigned long,
                 std::size_t, std::size_t, std::size_t, void*);

constexpr std::array<std::uint8_t, 3> kShellcode{0x33, 0xC0, 0xC3};
constexpr DWORD kThreadTimeoutMs = 5000;

bool is_nt_success(LONG status) {
    return status >= 0;
}

struct NtFunctions {
    NtAllocateVirtualMemoryFn allocate = nullptr;
    NtWriteVirtualMemoryFn write = nullptr;
    NtProtectVirtualMemoryFn protect = nullptr;
    NtCreateThreadExFn create_thread = nullptr;
};

bool resolve_functions(syscall::Engine& engine, NtFunctions& functions) {
    functions.allocate = engine.get<NtAllocateVirtualMemoryFn>("NtAllocateVirtualMemory");
    functions.write = engine.get<NtWriteVirtualMemoryFn>("NtWriteVirtualMemory");
    functions.protect = engine.get<NtProtectVirtualMemoryFn>("NtProtectVirtualMemory");
    functions.create_thread = engine.get<NtCreateThreadExFn>("NtCreateThreadEx");
    return functions.allocate != nullptr && functions.write != nullptr &&
           functions.protect != nullptr && functions.create_thread != nullptr;
}

void* allocate_rw(NtAllocateVirtualMemoryFn allocate, std::size_t size) {
    void* base = nullptr;
    std::size_t region = size;
    const LONG status = allocate(GetCurrentProcess(), &base, 0, &region,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return is_nt_success(status) ? base : nullptr;
}

bool write_bytes(NtWriteVirtualMemoryFn write, void* destination,
                 const void* source, std::size_t size) {
    std::size_t written = 0;
    const LONG status = write(GetCurrentProcess(), destination, source, size, &written);
    return is_nt_success(status) && written == size;
}

bool make_executable(NtProtectVirtualMemoryFn protect, void* base, std::size_t size) {
    void* address = base;
    std::size_t region = size;
    unsigned long previous = 0;
    const LONG status =
        protect(GetCurrentProcess(), &address, &region, PAGE_EXECUTE_READ, &previous);
    return is_nt_success(status);
}

HANDLE spawn(NtCreateThreadExFn create_thread, void* entry) {
    HANDLE thread = nullptr;
    const LONG status = create_thread(&thread, THREAD_ALL_ACCESS, nullptr,
                                      GetCurrentProcess(), entry, nullptr,
                                      0, 0, 0, 0, nullptr);
    return is_nt_success(status) ? thread : nullptr;
}

class AllocationGuard {
public:
    explicit AllocationGuard(void* base) : base_(base) {}
    ~AllocationGuard() {
        if (base_ != nullptr) {
            VirtualFree(base_, 0, MEM_RELEASE);
        }
    }
    AllocationGuard(const AllocationGuard&) = delete;
    AllocationGuard& operator=(const AllocationGuard&) = delete;

private:
    void* base_;
};

class HandleGuard {
public:
    explicit HandleGuard(HANDLE handle) : handle_(handle) {}
    ~HandleGuard() {
        if (handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

private:
    HANDLE handle_;
};

int run() {
    syscall::Engine engine;
    if (!engine.init(syscall::Mode::kIndirect)) {
        return 1;
    }

    NtFunctions functions;
    if (!resolve_functions(engine, functions)) {
        return 2;
    }
    if (!engine.commit()) {
        return 3;
    }

    void* memory = allocate_rw(functions.allocate, kShellcode.size());
    if (memory == nullptr) {
        return 4;
    }
    const AllocationGuard allocation(memory);

    if (!write_bytes(functions.write, memory, kShellcode.data(), kShellcode.size())) {
        return 5;
    }
    if (!make_executable(functions.protect, memory, kShellcode.size())) {
        return 6;
    }

    const HANDLE thread = spawn(functions.create_thread, memory);
    if (thread == nullptr) {
        return 7;
    }
    const HandleGuard handle(thread);

    WaitForSingleObject(thread, kThreadTimeoutMs);
    return 0;
}

}

int main() {
    return run();
}
