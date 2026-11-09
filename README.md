# syscall-engine

Direct and indirect syscall engine for Windows x64 with Halo's Gate system service number resolution.

## Overview

EDR products hook ntdll to inspect sensitive calls such as `NtAllocateVirtualMemory`. This library resolves the system service number for any exported ntdll function and emits its own syscall stubs, so execution reaches the kernel without touching hooked code.

Direct mode executes `syscall` from the trampoline region. Indirect mode jumps into ntdll's own `syscall; ret` gadget, keeping both the transition and the return address inside ntdll.

Built for red team tooling, EDR validation, and Windows internals research.

## Features

- Direct syscall stubs
- Indirect syscall stubs through a `syscall; ret` gadget found in an executable ntdll section
- Halo's Gate fallback: recovers service numbers from neighboring stubs when the target stub is hooked
- Portable core: PE parsing, SSN resolution, and stub assembly have no Windows dependency and are unit tested natively
- Explicit lifecycle: write stubs in read/write memory, then flip to read/execute with `commit`
- No external dependencies, C++20

## Architecture

| Component | Responsibility |
| --- | --- |
| `include/syscall/pe_types.hpp` | PE32+ structure layouts with compile-time size checks |
| `include/syscall/pe_image.hpp` | Bounds-checked header, section, and export parsing |
| `include/syscall/ssn_resolver.hpp` | Halo's Gate system service number resolution |
| `include/syscall/gadget_finder.hpp` | `syscall; ret` gadget discovery in executable sections |
| `include/syscall/trampoline.hpp` | Stub byte assembly for both modes |
| `include/syscall/engine.hpp` | Windows-facing engine: mode selection, allocation, commit |
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

using NtAllocateVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, void**, std::size_t, std::size_t*, unsigned long, unsigned long);

syscall::Engine engine;
if (!engine.init(syscall::Mode::kIndirect)) {
    return 1;
}

auto nt_allocate = engine.get<NtAllocateVirtualMemoryFn>("NtAllocateVirtualMemory");
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

## How it works

1. Parse the mapped ntdll image: headers, sections, export directory.
2. Resolve the SSN for the requested function. A clean stub exposes it directly. A hooked stub is recovered from the nearest clean neighbor by export order, which is Halo's Gate.
3. Emit a stub into the trampoline region.
4. Flip the region to read/execute with `commit`.
5. Call the stub like the original function.

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

The native suite covers 39 cases:

- PE header validation, corrupted signatures, truncated buffers
- Export parsing, ordinal bounds, unterminated names, missing directories
- Halo's Gate: direct resolution, previous and next neighbor recovery, chained hooked stubs, SSN underflow
- Gadget discovery: executable section filtering, absent patterns, sections outside the image, oversized declared sizes
- Stub assembly: exact byte sequences, undersized buffers, stride isolation

## Detection notes

Direct syscalls return to an address outside ntdll and are visible to call stack heuristics. Indirect syscalls move the transition and return into ntdll, which defeats the common checks. A determined stack walker can still inspect surrounding frames. Return address spoofing is the next layer, not included here.

## Legal

This project is intended for authorized security testing, EDR validation, and research on systems you own or have explicit written permission to test. You are responsible for how you use it.

## License

MIT. See `LICENSE`.
