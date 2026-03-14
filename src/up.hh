#pragma once

#include "cli.hh"
#include "error.hh"

namespace oo {

fn up(cli::cli &&cli) -> error_or<ok>;

} // namespace oo
