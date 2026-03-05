#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"

#include <optional>
#include <string>
#include <sys/types.h>

namespace oo {

// Stores namespace runtime state
// Persisted to /var/run/oo/<ns>/state.ini
struct namespace_state {
  pid_t daemon_pid{0};
  pid_t child_pid{0};
  u8 subnet_octet{0};
  std::string veth_host;
  std::string veth_ns;

  fn load(linux_namespace &ns) -> error_or<namespace_state>;
  fn save(linux_namespace &ns) const -> error_or<ok>;

private:
  static constexpr const char *STATE_FILE = "state.ini";
};

} // namespace oo
