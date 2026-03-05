#include "cli.hh"
#include "commands.hh"
#include "common.hh"
#include "debug.hh"
#include "error.hh"

namespace oo {

verbosity LOGGER_VERBOSITY = verbosity::nothing;

static fn entry(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo [-options] <up/down/exec/init> [-options] [args...]",
                   "todo");

  let &flag_verbose = cli.add_flag<cli::flag_repeated_boolean>(
      'v', "\0", "Increase verbosity.");
  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");
  let &flag_version = cli.add_flag<cli::flag_boolean>(
      '\0', "version", "Print version and debug information.");

  let subcommand = unwrap(cli.parse_args_until_subcommand());

  let v_count = flag_verbose.get_count();
  if (v_count == 1)
    LOGGER_VERBOSITY = verbosity::error;
  else if (v_count == 2)
    LOGGER_VERBOSITY = verbosity::info;
  else if (v_count == 3)
    LOGGER_VERBOSITY = verbosity::debug;
  else if (v_count >= 4)
    LOGGER_VERBOSITY = verbosity::all;

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }
  if (flag_version.is_enabled()) {
    cli::show_version();
    return ok{};
  }

  if (!subcommand.has_value())
    return make_error(
        "Missing a subcommand. Try '--help' for more information.");

  trace(verbosity::debug, "Executing {}", *subcommand);

  cli.reset_context();

  // clang-format off
  switch (hash_string(*subcommand)) {
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

int main(int argc, char **argv) {
  insist(argc >= 1);
  argc--;
  argv++;

  let cli = oo::cli::cli{argc, argv};

  if (let r = oo::entry(std::move(cli)); r.is_err()) {
    oo::cli::show_message("ERROR: " + r.get_error().get_owned_reason());
    return 1;
  }

  return 0;
}
