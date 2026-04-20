#include "init.hh"

#include "caps.hh"
#include "cli.hh"
#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"
#include "oorunner.hh"

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

  unwrap(oorunner::ensure_exists());
  let oor = unwrap(oorunner::lookup());

  unwrap(caps::set_file_capabilities(exe_path.c_str()));

  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec)) {
    std::filesystem::create_directories(constants::OO_RUN_DIR, ec);
    unwrap(oo_error_code(ec, std::string{"Failed to create "} +
                                 constants::OO_RUN_DIR));
    trace(verbosity::info, "Created {}", constants::OO_RUN_DIR);
  }

  // SECURITY: /var/run/oo is owned by the dedicated 'oorunner' system user.
  // The oo binary switches to that user at runtime start, so writes there
  // go through normal DAC checks. The invoking user retains only r-x on
  // this tree. Do not widen perms to 1777; that would allow anyone to
  // replace or remove entries.
  unwrap(
      oo_linux_syscall(chown, constants::OO_RUN_DIR.c_str(), oor.uid, oor.gid));

  using perms = std::filesystem::perms;
  std::filesystem::permissions(constants::OO_RUN_DIR,
                               perms::owner_all | perms::group_read |
                                   perms::group_exec | perms::others_read |
                                   perms::others_exec,
                               ec);
  unwrap(oo_error_code(ec, std::string{"Failed to set permissions on "}.append(
                               constants::OO_RUN_DIR)));

  // SECURITY: Self-heal. If this machine ran a pre-refactor oo, the parent
  // dir may contain entries owned by the invoking user or root with 0700
  // perms. Recursively reset ownership to oorunner so the new runtime
  // model can actually read and write them. Children are *not* chmod'ed
  // here; `oo up` will set correct perms when it recreates them, and the
  // user can always `oo down` and `oo up` again to resync a single ns.
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(constants::OO_RUN_DIR, ec))
  {
    if (ec) {
      return make_error("Failed to enumerate " +
                        std::string{constants::OO_RUN_DIR} + ": " +
                        ec.message());
    }
    unwrap(oo_linux_syscall(lchown, entry.path().c_str(), oor.uid, oor.gid));
  }

  trace(verbosity::info, "Updated {} to oorunner:oorunner 0755 (recursive)",
        constants::OO_RUN_DIR);

  // SECURITY: Final check -- ensure_runtime_dir_exists asserts that the
  // parent dir is now oorunner-owned. Any future code path that bypasses
  // init and leaves the dir in a bad state will trip this in `oo up`,
  // but catching it here too means init won't silently "succeed" on a
  // broken setup.
  unwrap(ensure_runtime_dir_exists());

  return ok{};
}

} // namespace oo
