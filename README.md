# syscall-engine

Direct, indirect, and stack-spoofed syscall engine for Windows x64 with fresh ntdll resolution and hashed export lookup.

## Overview

EDR products hook ntdll to inspect sensitive calls such as `NtAllocateVirtualMemory`. This library maps a clean copy of ntdll from `\KnownDlls`, resolves the system service number for any exported function there, and emits its own syscall stubs, so execution reaches the kernel without touching hooked code.

Direct mode executes `syscall` from the trampoline region. Indirect mode jumps into ntdll's own `syscall; ret` gadget, keeping both the transition and the return address inside ntdll. Spoofed indirect mode also rebuilds the return stack below the stub, so a kernel stack walk sees ntdll frames instead of the trampoline.

Built for red team tooling, EDR validation, and Windows internals research.

## Features

- Fresh ntdll resolution: maps `\KnownDlls\ntdll.dll` read-only and reads SSNs from the clean image, so inline hooks never reach the resolver
- Hashed resolution: `SC_HASH` evaluates FNV-1a at compile time, so `Nt*` names never appear as plaintext strings
- Live fallback: if the KnownDlls mapping is unavailable, resolution falls back to the loaded module and Halo's Gate
- Direct syscall stubs
- Indirect syscall stubs through a `syscall; ret` gadget found in an executable section of the live ntdll
- Stack-spoofed indirect stubs: three ntdll `ret` frames and a `leave; ret` terminator restore the real return address, while stack arguments 5 through 12 are copied into the fake frame
- CET aware: spoofed mode falls back to plain indirect when a user shadow stack is enabled or the required gadgets are missing
- Status codes: every engine call returns or records a `Status`, with `status_message` for diagnostics
- Stub cache: resolving the same export twice returns the same trampoline
- Halo's Gate fallback: recovers service numbers from neighboring stubs when a live stub is hooked
- Portable core: PE parsing, SSN resolution, gadget discovery, and stub assembly have no Windows dependency and are unit tested natively
- Explicit lifecycle: write stubs in read/write memory, then flip to read/execute with `commit`
- CMake package: `find_package(syscall-engine)` exports `syscall::core` and `syscall::windows`
- No external dependencies, C++20

## Architecture

| Component | Responsibility |
| --- | --- |
| `include/syscall/pe_types.hpp` | PE32+ structure layouts with compile-time size checks |
| `include/syscall/pe_image.hpp` | Bounds-checked header, section, and export parsing |
| `include/syscall/hash.hpp` | Compile-time FNV-1a hashing for export lookup |
| `include/syscall/status.hpp` | Engine status codes and diagnostic messages |
| `include/syscall/ssn_resolver.hpp` | Direct stub reads and Halo's Gate neighbor recovery |
| `include/syscall/gadget_finder.hpp` | `syscall; ret`, `ret`, and `leave; ret` gadget discovery in executable sections |
| `include/syscall/trampoline.hpp` | Stub byte assembly for all modes |
| `include/syscall/fresh_ntdll.hpp` | KnownDlls section mapping and unmapping |
| `include/syscall/mitigations.hpp` | User shadow stack (CET) detection |
| `include/syscall/engine.hpp` | Windows-facing engine: source selection, mode selection, allocation, commit |
| `src/main.cpp` | Example loader using indirect syscalls |

The portable core never includes `windows.h`. That keeps it testable on any platform and reusable in scanners or analysis tooling.

## Requirements

- CMake 3.20 or newer
- A C++20 compiler
- mingw-w64 for the Windows loader (Arch: `sudo pacman -S mingw-w64-gcc`)

## Build and test the portable core

```
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Cross-compile the loader

```
cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake
cmake --build build-win
```

The result is `build-win/syscall_loader.exe`.

## Install and consume

```
cmake --install build --prefix /your/prefix
```

```cmake
find_package(syscall-engine 0.3 REQUIRED)

target_link_libraries(app PRIVATE syscall::core)

if(WIN32)
    target_link_libraries(app PRIVATE syscall::windows)
endif()
```

`syscall::windows` exists only in Windows installs. `syscall::core` is portable.

## Usage

```cpp
#include "syscall/engine.hpp"
#include "syscall/hash.hpp"

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, std::size_t, std::size_t*, unsigned long, unsigned long);

syscall::Engine engine;
if (engine.init(syscall::Mode::kIndirectSpoofed) != syscall::Status::kOk) {
    return 1;
}

auto nt_allocate =
    engine.get<NtAllocateVirtualMemoryFn>(SC_HASH("NtAllocateVirtualMemory"));
if (nt_allocate == nullptr) {
    return 2;
}

if (engine.commit() != syscall::Status::kOk) {
    return 3;
}

void* base = nullptr;
std::size_t size = 0x1000;
nt_allocate(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Call resolved functions only after `commit`, because the trampoline region is read/write until then. The engine is not thread-safe; resolve stubs and commit from one thread.

`Engine::source()` reports whether the clean KnownDlls image or the live module supplied the SSNs. `Engine::mode()` reports the active mode after any fallback, and `Engine::last_error()` reports the status of the most recent call.

The `const char*` overloads remain for tooling. The hashed overloads keep function names out of the binary's string table.

## How it works

1. Parse the loaded ntdll to find the section mapping primitives and, in indirect and spoofed modes, the gadgets.
2. Map `\KnownDlls\ntdll.dll` as a read-only image and parse its exports. KnownDlls keeps the section the loader maps, while hooks live in the per-process copy. Fall back to the live module if the mapping fails.
3. Resolve the SSN for the requested function from the clean image, by name or by FNV-1a hash. A clean stub exposes it directly; on the live fallback, a hooked stub is recovered from the nearest clean neighbor by export order, which is Halo's Gate.
4. Emit a stub into the trampoline region. Spoofed mode also builds a fake return frame and copies the caller's stack arguments into it.
5. Flip the region to read/execute with `commit`.
6. Call the stub like the original function.

Direct stub layout:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0 | `4C 8B D1` | `mov r10, rcx` |
| 3 | `B8 <imm32>` | `mov eax, ssn` |
| 8 | `0F 05` | `syscall` |
| 10 | `C3` | `ret` |

Indirect stub layout:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0 | `4C 8B D1` | `mov r10, rcx` |
| 3 | `B8 <imm32>` | `mov eax, ssn` |
| 8 | `FF 25 00 00 00 00` | `jmp qword ptr [rip+0]` |
| 14 | `<uint64>` | absolute address of the ntdll gadget |

Spoofed indirect stub layout:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0 | `55` | `push rbp` |
| 1 | `48 89 E5` | `mov rbp, rsp` |
| 4 | `48 81 EC 00 01 00 00` | `sub rsp, 0x100` |
| 11 | `48 B8 <uint64>` | `mov rax, frame` for three frames at `[rsp]`, `[rsp+8]`, `[rsp+0x10]` |
| 55 | `48 B8 <uint64>` | `mov rax, terminator` stored at `[rsp+0x18]` |
| 70 | 104 bytes | copy stack arguments 5 through 12 from `[rsp+0x130]` to `[rsp+0x28]` |
| 174 | `4C 8B D1` | `mov r10, rcx` |
| 177 | `B8 <imm32>` | `mov eax, ssn` |
| 182 | `FF 25 00 00 00 00` | `jmp qword ptr [rip+0]` |
| 188 | `<uint64>` | absolute address of the ntdll syscall gadget |

The fake frames are plain `ret` sites inside ntdll. The terminator is a `leave; ret` site: it restores the saved RBP and the original return address, so the caller never sees the detour. Stubs live on a 256-byte stride in a 256 KiB trampoline region, which leaves 1024 slots.

## Testing

The native suite covers:

- PE header validation, corrupted signatures, truncated buffers
- Export parsing, ordinal bounds, unterminated names, missing directories
- Export lookup by name and FNV-1a hash, including empty, missing, and case-sensitive cases
- FNV-1a reference vectors and compile-time evaluation
- Status messages for every code, including out-of-range values
- Halo's Gate: direct resolution, previous and next neighbor recovery, chained hooked stubs, SSN underflow
- SSN resolution by export index, including out-of-range indexes
- Gadget discovery: executable section filtering, absent patterns, sections outside the image, oversized declared sizes
- Spoof gadget discovery: frame and terminator collection across sections, missing terminator, too few frames
- Stub assembly: exact byte sequences, undersized buffers, stride isolation
- Spoofed stub assembly: prologue and syscall tail bytes, embedded frame and terminator addresses, stack argument copies, exact stub size

The Windows suite, run in CI, covers:

- Fresh source selection in every mode
- Active mode reporting, including spoofed selection
- Resolution of known and unknown exports by name and hash
- Stub caching across name and hash lookups
- Direct, indirect, and spoofed stub execution through `NtQuerySystemTime`
- Stack argument forwarding through a spoofed `NtQueryVirtualMemory` call
- Resolve and commit lifecycle guards

## Detection notes

Direct syscalls return to an address outside ntdll and are visible to call stack heuristics. Indirect syscalls move the transition and return into ntdll, which defeats the common checks. Spoofed indirect syscalls rebuild the return stack, so the walk sees three `ret` frames and a `leave; ret` terminator inside ntdll before the original stack pointer.

The fake frame is synthetic. Walkers that validate unwind metadata per frame, or that check whether the return stack lives in committed anonymous memory, can still flag it; fully unwind-valid frames are future work. User shadow stacks make every fake return fault, so the engine detects the mitigation and downgrades to plain indirect.

SSNs come from a clean KnownDlls image, so inline hooks never reach the resolver, while the gadget still comes from the live module so the jump target stays inside ntdll's real address range. Hashed lookup keeps `Nt*` names out of the binary's string table for static signature scans.

## Releases

Tags matching `v*` trigger `.github/workflows/release.yml`. The workflow runs both test suites, builds `syscall_loader.exe` on Windows, generates release notes from the commit history, and attaches the loader with a SHA-256 checksum.

```
git tag v0.3.0
git push origin v0.3.0
```

Prerelease tags such as `v0.3.0-rc.1` are marked as prereleases automatically.

## Legal

This project is intended for authorized security testing, EDR validation, and research on systems you own or have explicit written permission to test. You are responsible for how you use it.

## License

MIT. See `LICENSE`.
