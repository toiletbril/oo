#include "common.hh"
#include "constants.hh"
#include "linux_util.hh"

#include <filesystem>

namespace oo {

fn ensure_runtime_dir_exists() -> error_or<ok> {
  std::error_code ec;
  let e = std::filesystem::exists(constants::OO_RUN_DIR, ec);
  unwrap(oo_error_code(ec, "Couldn't check if runtime directory exists"));
  if (!e) {
    return make_error(
        "Runtime directory does not exist. Please run 'init' first.");
  }
  return ok{};
}

} // namespace oo
