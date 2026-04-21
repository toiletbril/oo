#include "mountain.hh"

#include "debug.hh"
#include "linux_util.hh"

#include <sys/mount.h>
#include <sys/stat.h>
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

fn mountain::bind_mount(std::string source, std::string target) -> error_or<ok>
{
  trace_variables(verbosity::debug, source, target);
  insist(!source.empty() && !target.empty(),
         "bind_mount paths must be non-empty");
  insist(source.find('\0') == std::string::npos &&
             target.find('\0') == std::string::npos,
         "mount paths must not contain null bytes; C strings would truncate");
  unwrap(oo_linux_syscall(mount, source.c_str(), target.c_str(), nullptr,
                          MS_BIND, nullptr));

  // SECURITY: a bind mount makes source and target refer to the same inode
  // on the same device. A silent no-op (unusual but possible under seccomp
  // or a stacked filesystem) would leave the daemon seeing the host file.
  struct stat src_st{}, tgt_st{};
  unwrap(oo_linux_syscall(stat, source.c_str(), &src_st));
  unwrap(oo_linux_syscall(stat, target.c_str(), &tgt_st));
  insist(src_st.st_dev == tgt_st.st_dev && src_st.st_ino == tgt_st.st_ino,
         "bind mount did not attach: source and target still differ");

  trace(verbosity::info, "Bind mounted {} to {}", source, target);
  m_mounted_paths.emplace_back(std::move(target));
  return ok{};
}

fn mountain::cleanup() -> error_or<ok>
{
  for (let it = m_mounted_paths.rbegin(); it != m_mounted_paths.rend(); ++it) {
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
