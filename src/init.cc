#include "init.hh"

#include "caps.hh"
#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <filesystem>
#include <sys/statvfs.h>
#include <unistd.h>

namespace oo {

fn init(cli::cli &&cli) -> error_or<ok>
{
  cli.add_use_case("oo init [-options]",
                   "Set file capabilities on the binary (requires root).");

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

  struct statvfs vfs{};
  unwrap(oo_linux_syscall(statvfs, exe_path.c_str(), &vfs));
  if (vfs.f_flag & ST_NOSUID) {
    return make_error(
        "Binary is on a nosuid mount; the kernel will not honor file "
        "capabilities. Move oo to a non-nosuid filesystem and re-run init.");
  }

  unwrap(caps::set_file_capabilities(exe_path.c_str()));

  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec)) {
    std::filesystem::create_directories(constants::OO_RUN_DIR, ec);
    unwrap(oo_error_code(ec, std::string{"Failed to create "} +
                                 constants::OO_RUN_DIR));
    trace(verbosity::info, "Created {} with owner-only write permissions",
          constants::OO_RUN_DIR);
  }

  // SECURITY: 0755 (rwxr-xr-x) prevents unprivileged users from creating or
  // deleting entries in the parent directory. The binary uses CAP_DAC_OVERRIDE
  // to create per-user namespace subdirectories despite not owning the dir.
  // Do not change to 1777 (world-writable); that allows any user to pollute
  // the global namespace by creating or removing entries here.
  std::filesystem::permissions(constants::OO_RUN_DIR,
                               std::filesystem::perms::owner_all |
                                   std::filesystem::perms::group_read |
                                   std::filesystem::perms::group_exec |
                                   std::filesystem::perms::others_read |
                                   std::filesystem::perms::others_exec,
                               ec);
  unwrap(oo_error_code(ec, std::string{"Failed to set permissions on "}.append(
                               constants::OO_RUN_DIR)));

  trace(verbosity::info, "Updated {} permissions to 0755",
        constants::OO_RUN_DIR);

  return ok{};
}

} // namespace oo
