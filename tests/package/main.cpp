#include "syscall/status.hpp"

#ifdef _WIN32
#include "syscall/mitigations.hpp"
#endif

int main() {
#ifdef _WIN32
    (void)syscall::is_user_shadow_stack_enabled();
#endif
    return syscall::status_message(syscall::Status::kOk) != nullptr ? 0 : 1;
}
