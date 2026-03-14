#include "init.hh"
#include "caps.hh"
#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <filesystem>
#include <unistd.h>

namespace oo {

fn init(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo init [-options]", "todo");

  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  std::string exe_path =
      std::filesystem::read_symlink(constants::PROC_SELF_EXE);
  trace(verbosity::info, "Setting capabilities for: {}", exe_path);

  // Make sure we're the root user.
  if (geteuid() != 0) {
    return make_error("'init' must be run with sudo.");
  }

  // CAP_SYS_ADMIN: Required for unshare(CLONE_NEWNET|CLONE_NEWNS).
  // CAP_NET_ADMIN: Required for network configuration (netlink, routes, etc).
  // CAP_SYS_PTRACE: Required for setns() to enter namespaces.

  unwrap(caps::set_file_capabilities(exe_path.c_str()));

  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec)) {
    std::filesystem::create_directories(constants::OO_RUN_DIR, ec);
    unwrap(oo_error_code(ec, std::string{"Failed to create "} +
                                 constants::OO_RUN_DIR));
    trace(verbosity::info, "Created {} with world-writable permissions",
          constants::OO_RUN_DIR);
  }

  std::filesystem::permissions(constants::OO_RUN_DIR,
                               std::filesystem::perms::sticky_bit |
                                   std::filesystem::perms::owner_all |
                                   std::filesystem::perms::group_all |
                                   std::filesystem::perms::others_all,
                               ec);
  unwrap(oo_error_code(ec, std::string{"Failed to set permissions on "}.append(
                               constants::OO_RUN_DIR)));

  trace(verbosity::info, "Updated {} permissions to 1777",
        constants::OO_RUN_DIR);

  return ok{};
}

} // namespace oo
