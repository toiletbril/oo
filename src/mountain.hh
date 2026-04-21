#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"

#include <string>
#include <vector>

namespace oo {

// Handles bind mount operations for namespace isolation
// Makes root private and bind mounts DNS config files
class mountain
{
public:
  mountain(linux_namespace &ns);
  ~mountain() = default;

  // Make root mount private (MS_REC | MS_PRIVATE).
  [[nodiscard]] fn make_root_private() -> error_or<ok>;

  // Bind mount a file. Takes owning strings so .c_str() is guaranteed
  // null-terminated for the mount syscall.
  [[nodiscard]] fn bind_mount(std::string source, std::string target)
      -> error_or<ok>;

  // Unmount all tracked mounts.
  fn cleanup() -> error_or<ok>;

private:
  linux_namespace &m_ns;
  std::vector<std::string> m_mounted_paths;
};

} // namespace oo
