#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/capability.h>

namespace oo {

namespace caps {

fn raise_ambient_capabilities() -> error_or<ok>;
fn set_file_capabilities(const char *path) -> error_or<ok>;

} // namespace caps

} // namespace oo
