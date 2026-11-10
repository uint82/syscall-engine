#include "syscall/status.hpp"

namespace syscall {

const char* status_message(Status status) {
    switch (status) {
        case Status::kOk:
            return "ok";
        case Status::kInvalidArgument:
            return "invalid argument";
        case Status::kAlreadyInitialized:
            return "engine is already initialized";
        case Status::kNotInitialized:
            return "engine is not initialized";
        case Status::kLiveImageUnavailable:
            return "live ntdll image is unavailable";
        case Status::kExportTableUnavailable:
            return "export table is unavailable";
        case Status::kGadgetNotFound:
            return "syscall gadget not found";
        case Status::kTrampolineAllocationFailed:
            return "trampoline allocation failed";
        case Status::kTrampolineExhausted:
            return "trampoline slots are exhausted";
        case Status::kStubWriteFailed:
            return "stub encoding failed";
        case Status::kUnknownExport:
            return "export not found";
        case Status::kNoSyscallNumber:
            return "export has no syscall number";
        case Status::kAlreadyCommitted:
            return "engine is already committed";
        case Status::kProtectionFailed:
            return "trampoline protection failed";
    }
    return "unknown status";
}

}
