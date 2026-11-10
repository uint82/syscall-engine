#pragma once

namespace syscall {

enum class Status {
    kOk,
    kInvalidArgument,
    kAlreadyInitialized,
    kNotInitialized,
    kLiveImageUnavailable,
    kExportTableUnavailable,
    kGadgetNotFound,
    kTrampolineAllocationFailed,
    kTrampolineExhausted,
    kStubWriteFailed,
    kUnknownExport,
    kNoSyscallNumber,
    kAlreadyCommitted,
    kProtectionFailed,
    kGadgetInvalid,
};

const char* status_message(Status status);

}
