#include "test_harness.hpp"

#include "syscall/status.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace {

constexpr std::array<syscall::Status, 14> kStatuses{
    syscall::Status::kOk,
    syscall::Status::kInvalidArgument,
    syscall::Status::kAlreadyInitialized,
    syscall::Status::kNotInitialized,
    syscall::Status::kLiveImageUnavailable,
    syscall::Status::kExportTableUnavailable,
    syscall::Status::kGadgetNotFound,
    syscall::Status::kTrampolineAllocationFailed,
    syscall::Status::kTrampolineExhausted,
    syscall::Status::kStubWriteFailed,
    syscall::Status::kUnknownExport,
    syscall::Status::kNoSyscallNumber,
    syscall::Status::kAlreadyCommitted,
    syscall::Status::kProtectionFailed,
};

}

SC_TEST_CASE("every status code has a message") {
    for (const auto status : kStatuses) {
        const char* message = syscall::status_message(status);
        SC_REQUIRE(message != nullptr);
        SC_REQUIRE(message[0] != '\0');
    }
}

SC_TEST_CASE("status messages are distinct") {
    for (std::size_t left = 0; left < kStatuses.size(); ++left) {
        for (std::size_t right = left + 1; right < kStatuses.size(); ++right) {
            SC_REQUIRE(
                std::string(syscall::status_message(kStatuses[left])) !=
                std::string(syscall::status_message(kStatuses[right])));
        }
    }
}

SC_TEST_CASE("an out of range status reports unknown") {
    const auto message = syscall::status_message(static_cast<syscall::Status>(0xFF));
    SC_REQUIRE_EQ(std::string("unknown status"), std::string(message));
}
