#include "common.hh"

#include "constants.hh"
#include "linux_util.hh"
#include "oorunner.hh"

#include <filesystem>
#include <sys/stat.h>

namespace oo {

fn ensure_runtime_dir_exists() -> error_or<ok>
{
  std::error_code ec;
  let e = std::filesystem::exists(constants::OO_RUN_DIR, ec);
  unwrap(oo_error_code(ec, "Couldn't check if runtime directory exists"));
  if (!e) {
    return make_error(
        "Runtime directory does not exist. Please run 'init' first.");
  }

  // SECURITY: Enforce that /var/run/oo is owned by oorunner. A stale
  // root-owned directory from a previous install would silently bypass
  // the oorunner-based permission model; refuse to run until `oo init`
  // fixes ownership.
  struct stat st{};
  unwrap(oo_linux_syscall(stat, constants::OO_RUN_DIR.c_str(), &st));
  let oor = unwrap(oorunner::lookup());
  if (st.st_uid != oor.uid) {
    return make_error(
        std::string{constants::OO_RUN_DIR} +
        " is not owned by 'oorunner'. Re-run 'sudo oo init' to fix.");
  }

  return ok{};
}

} // namespace oo
