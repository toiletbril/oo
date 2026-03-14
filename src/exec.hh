#pragma once

#include "cli.hh"
#include "error.hh"

namespace oo {

fn exec(cli::cli &&cli) -> error_or<ok>;

} // namespace oo
