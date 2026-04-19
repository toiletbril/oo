#include "exec.hh"
#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_namespace.hh"
#include "satan.hh"

#include <filesystem>

namespace oo {

fn exec(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo exec [-options] <namespace> [--] <command> [args...]",
                   "Run a command inside a running namespace.");

  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  if (args.empty()) {
    return make_error(
        "Missing namespace name. Try '--help' for more information.");
  }

  if (args.size() < 2) {
    return make_error("Missing command. Try '--help' for more information.");
  }

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  args.erase(args.begin());

  linux_namespace ns{ns_name};
  satan s{ns};

  unwrap(s.execute(args));

  unreachable();
}

} // namespace oo
