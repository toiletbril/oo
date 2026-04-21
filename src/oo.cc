#include "cli.hh"
#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "down.hh"
#include "error.hh"
#include "exec.hh"
#include "init.hh"
#include "up.hh"

namespace oo {

verbosity LOGGER_VERBOSITY = verbosity::nothing;

static fn entry(cli::cli &&cli) -> error_or<ok>
{
  cli.add_use_case(
      "oo [-options] up [-options] <namespace> [--] <daemon command>",
      "Create namespace and start a daemon.");
  cli.add_use_case("oo [-options] down [-options] <namespace>",
                   "Remove namespace and shutdown the daemon.");
  cli.add_use_case("oo [-options] exec [-options] <namespace> [--] <command>",
                   "Execute a command inside a namespace.");
  cli.add_use_case("oo [-options] init [-options]",
                   "Give necessary capabilities to the oo binary.");

  let &flag_verbose = cli.add_flag<cli::flag_repeated_boolean>(
      'v', "\0", "Increase verbosity.");
  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");
  let &flag_version = cli.add_flag<cli::flag_boolean>(
      '\0', "version", "Print version and debug information.");

  let subcommand = unwrap(cli.parse_args_until_subcommand());

  let v = flag_verbose.get_count();

  if (v >= static_cast<usize>(verbosity::all))
    LOGGER_VERBOSITY = verbosity::all;
  else
    LOGGER_VERBOSITY = static_cast<verbosity>(v);

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }
  if (flag_version.is_enabled()) {
    cli::show_version();
    return ok{};
  }

  if (!subcommand.has_value()) {
    return make_error(
        "Missing a subcommand. Try '--help' for more information.");
  }

  trace(verbosity::debug, "Executing {}", *subcommand);

  cli.reset_context();

  // SECURITY: Privilege posture is now set per-subcommand. `init` stays
  // root; `up` and `exec` drop to oorunner on entry; `down` defers its
  // drop until after the kill so the SIGTERM goes out at the invoking
  // uid (the daemon is owned by that user). See each subcommand for
  // the matching `privilege_drop::switch_to_oorunner` call.

  // clang-format off
  string_switch (*subcommand) {
  string_case("up"):
  string_case("u"): {
    return up(std::move(cli));
  }

  string_case("down"):
  string_case("d"): {
    return down(std::move(cli));
  }

  string_case("exec"):
  string_case("e"): {
    return exec(std::move(cli));
  }

  string_case("init"):
  string_case("i"): {
    return init(std::move(cli));
  }

  default:
    return make_error("Unknown subcommand '" + *subcommand +
                      "'. Try '--help' for more information.");
  }
  // clang-format off
}

} // namespace oo

fn main(int argc, char **argv) -> int
{
  insist(argc >= 1);
  argc--;
  argv++;

  let cli = oo::cli::cli{argc, argv};

  if (let r = oo::entry(std::move(cli)); r.is_err()) {
    oo::cli::show_message("error: " + r.get_error().get_owned_reason());
    return 1;
  }

  return 0;
}
