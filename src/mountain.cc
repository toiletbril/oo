#include "mountain.hh"

#include "debug.hh"
#include "linux_util.hh"

#include <sys/mount.h>
#include <unistd.h>

namespace oo {

mountain::mountain(linux_namespace &ns) : m_ns(ns) {}

fn mountain::make_root_private() -> error_or<ok>
{
  unwrap(
      oo_linux_syscall(mount, "", "/", nullptr, MS_REC | MS_PRIVATE, nullptr));
  trace(verbosity::debug, "Made root mount private");
  return ok{};
}

fn mountain::bind_mount(std::string_view source, std::string_view target)
    -> error_or<ok>
{
  trace_variables(verbosity::debug, source, target);
  unwrap(oo_linux_syscall(mount, source.data(), target.data(), nullptr, MS_BIND,
                          nullptr));
  m_mounted_paths.emplace_back(target);
  trace(verbosity::info, "Bind mounted {} to {}", source, target);
  return ok{};
}

fn mountain::cleanup() -> error_or<ok>
{
  for (auto it = m_mounted_paths.rbegin(); it != m_mounted_paths.rend(); ++it) {
    let result = oo_linux_syscall(umount, it->c_str());
    if (result.is_err()) {
      trace(verbosity::error, "Failed to unmount {}: {}", *it,
            result.get_error().get_reason());
    } else {
      trace(verbosity::debug, "Unmounted {}", *it);
    }
  }

  m_mounted_paths.clear();

  return ok{};
}

} // namespace oo
