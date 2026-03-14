#pragma once

#include "cli.hh"
#include "error.hh"

namespace oo {

fn init(cli::cli &&cli) -> error_or<ok>;

} // namespace oo
