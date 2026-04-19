#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/capability.h>

namespace oo {

namespace caps {

// Set file capabilities on the binary during `oo init`.
fn set_file_capabilities(const char *path) -> error_or<ok>;

// Drop effective and inheritable capabilities and clear the ambient set.
// Call this in every child process immediately before execvp so that the
// exec'd binary inherits no elevated privileges.
fn drop_for_exec() -> error_or<ok>;

} // namespace caps

} // namespace oo
