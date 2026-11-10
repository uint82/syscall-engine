# Security posture

This document describes what `syscall-engine` does, what it does not do, and what still sees it. It is the technical companion to [`SECURITY.md`](../SECURITY.md), which covers reporting and safe harbor.

The engine is an evasion component, not a cloak of invisibility. Treat it as one layer in a test or red team toolchain, not as a guarantee that a payload stays unseen.

## Scope and limitations

`syscall-engine` is a user-mode x64 Windows library. It assumes the operator already has code execution in the target process. It is not an exploit, a privilege escalation, a sandbox escape, or a persistence mechanism.

- Platform: Windows 10 and 11, x64. ARM64 is not supported.
- Execution model: user-mode only. The library does not load a kernel driver and does not cross a privilege boundary.
- Threat model: the operator controls the process that calls the engine. The library does not target another process, inject into a remote process, or survive process exit.
- Payload: the library provides syscall stubs and a loader primitive. It does not provide a payload, encryption, packing, C2, persistence, credential access, anti-debug, or sandbox evasion.
- Hook bypass: the engine bypasses user-mode hooks at the entry of the resolved ntdll function. It does not bypass kernel callbacks, ETW, memory scanners, behavioral analytics, network detection, hardware breakpoints, or a human analyst.
- Gadget integrity: indirect and spoofed modes jump to a `syscall` gadget in the live ntdll. If an EDR patches that gadget, the call can fail or land in the patched code. The engine does not verify gadget integrity yet.
- Unwind-valid frames: the fake frames are leaf ntdll functions with empty unwind info, so a walker that trusts ntdll `.pdata` sees a consistent chain. The frames live in the stub's anonymous stack region. A walker that checks the memory type, cross-checks the chain against the thread start, or captures the kernel stack can still flag it.
- CET: the engine detects a user shadow stack and downgrades to plain indirect. It does not bypass hardware shadow stacks.
- Thread safety: the engine is not thread-safe. Resolve and commit from one thread. Stubs are read-only after commit, but `last_error` and mode state are not synchronized.
- Detection is expected: the library is an evasion component, not a stealth guarantee. AV and EDR may flag compiled loaders as hacktools or loaders. That is a false positive for the library, not a vulnerability.
- Authorization: use only on systems you own or have written permission to test.

## Detection surface

### What the engine changes

Direct syscalls return to an address outside ntdll, which call stack heuristics can see. Indirect syscalls move the transition and the return into ntdll. Spoofed indirect syscalls rebuild the return stack below the stub, so a walk sees ntdll `ret` frames and a `leave; ret` terminator. Unwind-valid spoofed syscalls use a leaf `syscall; ret` gadget and four leaf `ret` sites, each with a matching `.pdata` entry.

SSNs come from a clean KnownDlls image, so inline hooks never reach the resolver. The gadget comes from the live module, so the jump target stays inside ntdll's real address range. Hashed lookup keeps `Nt*` names out of the string table.

### What still sees it

| Telemetry | Why the engine is still visible |
| --- | --- |
| Kernel thread and process callbacks | `NtCreateThreadEx` creates a real thread. `PsSetCreateThreadNotifyRoutine` and process or thread telemetry see it. |
| ETW Threat Intelligence | ETW TI is kernel-level. The engine does not patch ETW, so allocation, protection, write, and thread events still reach the provider. |
| Memory scanning | The loader writes a payload into private memory and flips it to executable. EDR can scan private RWX or RX regions and the payload bytes. |
| Behavioral analytics | Allocate, write, protect, create thread is a classic injection chain. Behavior rules do not need to see the syscall instruction to flag the sequence. |
| Stack walkers with their own logic | The fake frames are valid leaf functions, but the chain lives in anonymous stack memory. A walker that checks the memory type, cross-checks the chain, or captures the kernel stack can still flag it. |
| Handle and object telemetry | The loader creates and closes thread handles. Kernel object callbacks see the objects. |
| Image load | The engine and loader are normal images. The loader is unsigned and may be flagged by reputation. |
| User-mode ETW and AMSI | The engine does not patch `EtwEventWrite` or AMSI. Payload behavior that emits events or content still reaches those providers. |
| Network | If the payload beacons or downloads, network detection still applies. The engine does not provide C2. |
| User-mode hooks on other functions | The engine bypasses the resolved ntdll entry. Hooks in kernel32, other DLLs, deeper ntdll code, or hardware breakpoints are outside the engine's scope. |

### Defensive checks

- Flag private memory that becomes executable after a write. Correlate `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtProtectVirtualMemory` at the kernel or ETW level.
- Flag thread start addresses that fall in private executable memory.
- Inspect return addresses for ntdll `ret` sites inside leaf functions that are not the function entry. The unwind-valid frames point at such sites.
- Compare the return address chain with the actual stack and the thread start. The fake chain ends at a sentinel and does not match a real call path.
- Check whether the return stack lives in a committed image region or anonymous stack memory. The stub's fake frames live in its own anonymous stack frame.
- Prefer kernel callbacks, ETW TI, and hardware breakpoints over user-mode ntdll hooks for high-value events.
- Treat allocate, write, protect, thread as a sequence, not as isolated events.

### Detection validation

The engine is useful as a controlled test target. Run the PoC suite in a lab, capture the telemetry, and tune detections against the three stages: the inline hook bypass, the unwind-valid fake stack, and the benign loader. The loader writes a magic value, so it is safe to run on a test host.

## ATT&CK mapping

The engine is a component, not an end-to-end procedure. The table maps the capability to ATT&CK techniques and states what the engine does not cover. The IDs are descriptive, not a claim of full technique coverage.

| Technique | ID | Engine contribution | Not covered |
| --- | --- | --- | --- |
| Native API | T1106 | Resolves SSNs and emits direct, indirect, and spoofed stubs. | No kernel driver, no new syscalls, no syscall number discovery beyond ntdll exports. |
| Dynamic API Resolution | T1027.007 | FNV-1a hashed export lookup keeps `Nt*` names out of the string table. | Other strings are not encrypted, and imports are still visible. |
| Process Injection | T1055 | The example and PoC provide the loader primitive: allocate, write, protect, create thread, wait, free. | No remote process injection, APC injection, thread hijacking, or PE mapping. |
| Impair Defenses | T1562 | Bypasses user-mode ntdll entry hooks and supports unwind-valid frames. | Does not disable ETW, AMSI, kernel callbacks, EDR services, or hardware breakpoints. |
| Obfuscated Files or Information | T1027 | Call stack spoofing hides the stub's return path from naive walkers. | No payload encryption, packing, or string obfuscation. |

T1055 is the closest match for the loader primitive. The engine does not implement a full injection technique by itself; the operator supplies the target and the payload.

## References

- [ATT&CK T1106](https://attack.mitre.org/techniques/T1106/)
- [ATT&CK T1027.007](https://attack.mitre.org/techniques/T1027/007/)
- [ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- [ATT&CK T1562](https://attack.mitre.org/techniques/T1562/)
- [ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)

## Reporting

See [`SECURITY.md`](../SECURITY.md) for reporting, supported versions, and safe harbor.
