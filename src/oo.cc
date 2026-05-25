#include "cli.hh"
#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "down.hh"
#include "edit.hh"
#include "error.hh"
#include "exec.hh"
#include "init.hh"
#include "linux_util.hh"
#include "status.hh"
#include "up.hh"

#include <csignal>
#include <sys/prctl.h>

namespace oo {

verbosity LOGGER_VERBOSITY = verbosity::nothing;

static fn entry(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case(
      "oo [-options] up [-options] <namespace> [--] <daemon command>",
      "Create namespace and start a daemon.");
  cli.add_use_case("oo [-options] down [-options] <namespace>",
                   "Remove namespace and shutdown the daemon.");
  cli.add_use_case("oo [-options] exec [-options] <namespace> [--] <command>",
                   "Execute a command inside a namespace.");
  cli.add_use_case("oo [-options] edit [-options] <namespace> [--] [command]",
                   "Edit a running namespace.");
  cli.add_use_case("oo [-options] status [<namespace>]",
                   "Show the state of one namespace, or list all of them.");
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

  string_case("edit"):
  string_case("x"): {
    return edit(std::move(cli));
  }

  string_case("status"):
  string_case("s"): {
    return status(std::move(cli));
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

// SECURITY: oo drops privileges with setuid in its forked children, which
// clears the dumpable flag. LeakSanitizer scans memory at exit via ptrace,
// which the kernel forbids on a non-dumpable process, so under the asan build
// every privilege-dropping process would abort with a LeakSanitizer fatal
// error. Disable leak detection here rather than via ASAN_OPTIONS, since the
// capability binary runs in secure-execution mode where that env is ignored.
// The address checker itself is unaffected.
extern "C" const char *__lsan_default_options() { return "detect_leaks=0"; }

fn main(int argc, char **argv) -> int
{
  insist(argc >= 1);

  // Ignore SIGPIPE process-wide so a peer that closes a socket or pipe early
  // turns into an EPIPE the caller can handle rather than killing the process.
  unused(::signal(SIGPIPE, SIG_IGN));

  oo::linux::init_process_name(argc, argv);
  argc--;
  argv++;

  let cli = oo::cli::cli{argc, argv};

  if (let r = oo::entry(std::move(cli)); r.is_err()) {
    oo::cli::show_message("error: " + r.get_error().get_owned_reason());
    return 1;
  }

  return 0;
}
