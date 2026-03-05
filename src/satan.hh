#pragma once

#include "cli.hh"
#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

namespace oo {

class satan {
public:
  satan(linux_namespace &ns) : m_ns(ns) {}

  // Spawn daemon with optional DNS config paths for bind mounting
  fn spawn_daemon(const std::vector<std::string> &daemonized_argv,
                  std::string_view resolv_conf_path = "",
                  std::string_view nsswitch_conf_path = "") -> error_or<pid_t>;

  // Execute command in existing namespace (does not return on success)
  fn execute(const std::vector<std::string> &argv) -> error_or<ok>;

private:
  linux_namespace &m_ns;

  fn enter_namespace(pid_t daemon_pid) -> error_or<ok>;
};

} // namespace oo
