#include "syscall/mitigations.hpp"

#include <windows.h>

namespace syscall {

bool is_user_shadow_stack_enabled() {
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy{};
    if (GetProcessMitigationPolicy(
            GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy)) == 0) {
        return false;
    }
    return policy.EnableUserShadowStack != 0;
}

}
