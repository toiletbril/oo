#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/capability.h>

namespace oo {

namespace caps {

// Set file capabilities on the binary during `oo init`.
[[nodiscard]] fn set_file_capabilities(const char *path) -> error_or<ok>;

// Drop effective and inheritable capabilities and clear the ambient set.
// Call this in every child process immediately before execvp so that the
// exec'd binary inherits no elevated privileges. SECURITY: silently
// discarding this error would leave an exec'd child holding elevated caps.
[[nodiscard]] fn drop_all_caps() -> error_or<ok>;

// Same as drop_all_caps() but keeps one or more capabilities live across
// execve. Each kept cap is left in CAP_EFFECTIVE and CAP_INHERITABLE,
// raised into the ambient set so it transitions through execve, and every
// other cap in CAP_LIST is cleared. SECURITY: every kept cap must be a
// member of CAP_LIST (i.e., one the binary is entitled to) or this
// function returns an error.
//
// Call via the `drop_all_caps_except(cap, ...)` macro below so the sentinel
// terminator is always appended. Calling drop_all_caps_except_impl directly
// without a trailing 0 is undefined behavior.
[[nodiscard]] fn drop_all_caps_except_impl(cap_value_t first, ...)
    -> error_or<ok>;

#define drop_all_caps_except(...) drop_all_caps_except_impl(__VA_ARGS__, 0)

} // namespace caps

} // namespace oo
