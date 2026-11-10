# syscall-engine

Direct and indirect syscall engine for Windows x64 with fresh ntdll resolution and hashed export lookup.

## Overview

EDR products hook ntdll to inspect sensitive calls such as `NtAllocateVirtualMemory`. This library maps a clean copy of ntdll from `\KnownDlls`, resolves the system service number for any exported function there, and emits its own syscall stubs, so execution reaches the kernel without touching hooked code.

Direct mode executes `syscall` from the trampoline region. Indirect mode jumps into ntdll's own `syscall; ret` gadget, keeping both the transition and the return address inside ntdll.

Built for red team tooling, EDR validation, and Windows internals research.

## Features

- Fresh ntdll resolution: maps `\KnownDlls\ntdll.dll` read-only and reads SSNs from the clean image, so inline hooks never reach the resolver
- Hashed resolution: `SC_HASH` evaluates FNV-1a at compile time, so `Nt*` names never appear as plaintext strings
- Live fallback: if the KnownDlls mapping is unavailable, resolution falls back to the loaded module and Halo's Gate
- Direct syscall stubs
- Indirect syscall stubs through a `syscall; ret` gadget found in an executable section of the live ntdll
- Halo's Gate fallback: recovers service numbers from neighboring stubs when a live stub is hooked
- Portable core: PE parsing, SSN resolution, and stub assembly have no Windows dependency and are unit tested natively
- Explicit lifecycle: write stubs in read/write memory, then flip to read/execute with `commit`
- No external dependencies, C++20

## Architecture

| Component | Responsibility |
| --- | --- |
| `include/syscall/pe_types.hpp` | PE32+ structure layouts with compile-time size checks |
| `include/syscall/pe_image.hpp` | Bounds-checked header, section, and export parsing |
| `include/syscall/hash.hpp` | Compile-time FNV-1a hashing for export lookup |
| `include/syscall/ssn_resolver.hpp` | Direct stub reads and Halo's Gate neighbor recovery |
| `include/syscall/gadget_finder.hpp` | `syscall; ret` gadget discovery in executable sections |
| `include/syscall/trampoline.hpp` | Stub byte assembly for both modes |
| `include/syscall/fresh_ntdll.hpp` | KnownDlls section mapping and unmapping |
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

## Usage

```cpp
#include "syscall/engine.hpp"
#include "syscall/hash.hpp"

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, std::size_t, std::size_t*, unsigned long, unsigned long);

syscall::Engine engine;
if (!engine.init(syscall::Mode::kIndirect)) {
    return 1;
}

auto nt_allocate =
    engine.get<NtAllocateVirtualMemoryFn>(SC_HASH("NtAllocateVirtualMemory"));
if (nt_allocate == nullptr) {
    return 2;
}

if (!engine.commit()) {
    return 3;
}

void* base = nullptr;
std::size_t size = 0x1000;
nt_allocate(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Call resolved functions only after `commit`, because the trampoline region is read/write until then.

The `const char*` overloads remain for tooling. The hashed overloads keep function names out of the binary's string table.

`Engine::source()` reports whether the clean KnownDlls image or the live module supplied the SSNs. Both paths resolve and execute the same way; the difference is what an inline hook can see.

## How it works

1. Parse the loaded ntdll to find the section mapping primitives and, in indirect mode, the gadget.
2. Map `\KnownDlls\ntdll.dll` as a read-only image and parse its exports. KnownDlls keeps the section the loader maps, while hooks live in the per-process copy. Fall back to the live module if the mapping fails.
3. Resolve the SSN for the requested function from the clean image, by name or by FNV-1a hash. A clean stub exposes it directly; on the live fallback, a hooked stub is recovered from the nearest clean neighbor by export order, which is Halo's Gate.
4. Emit a stub into the trampoline region.
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

Stubs live on a 32-byte stride, so direct and indirect formats share one region safely.

## Testing

The native suite covers:

- PE header validation, corrupted signatures, truncated buffers
- Export parsing, ordinal bounds, unterminated names, missing directories
- Export lookup by name and FNV-1a hash, including empty, missing, and case-sensitive cases
- FNV-1a reference vectors and compile-time evaluation
- Halo's Gate: direct resolution, previous and next neighbor recovery, chained hooked stubs, SSN underflow
- SSN resolution by export index, including out-of-range indexes
- Gadget discovery: executable section filtering, absent patterns, sections outside the image, oversized declared sizes
- Stub assembly: exact byte sequences, undersized buffers, stride isolation

The Windows suite, run in CI, covers:

- Fresh source selection in both modes
- Resolution of known and unknown exports by name and hash
- Direct and indirect stub execution through `NtQuerySystemTime`
- Hashed stub execution in both modes
- Resolve and commit lifecycle guards

## Detection notes

Direct syscalls return to an address outside ntdll and are visible to call stack heuristics. Indirect syscalls move the transition and return into ntdll, which defeats the common checks. SSNs come from a clean KnownDlls image, so inline hooks never reach the resolver, while the indirect gadget still comes from the live module so the jump target stays inside ntdll's real address range. Hashed lookup keeps `Nt*` names out of the binary's string table for static signature scans. A determined stack walker can still inspect surrounding frames. Return address spoofing is the next layer, not included here.

## Releases

Tags matching `v*` trigger `.github/workflows/release.yml`. The workflow runs both test suites, builds `syscall_loader.exe` on Windows, generates release notes from the commit history, and attaches the loader with a SHA-256 checksum.

```
git tag v0.2.0
git push origin v0.2.0
```

Prerelease tags such as `v0.2.0-rc.1` are marked as prereleases automatically.

## Legal

This project is intended for authorized security testing, EDR validation, and research on systems you own or have explicit written permission to test. You are responsible for how you use it.

## License

MIT. See `LICENSE`.
