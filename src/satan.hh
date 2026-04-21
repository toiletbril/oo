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

// Invoking user's uid/gid captured before the process switches to oorunner.
// Set exactly once in oo.cc before dispatching a runtime subcommand and
// read by the exec paths in satan.cc so they can drop back to this user
// before the final execvp.
//
// SECURITY: If these are read before they have been set (e.g. from a new
// code path added outside the subcommand dispatcher), child processes would
// exec as uid=0-of-oorunner. Tests assert the uid matches the invoking
// user to catch that regression.
extern uid_t INVOKING_UID;
extern gid_t INVOKING_GID;

class satan
{
public:
  satan(linux_namespace &ns) : m_ns(ns) {}

  // Spawn daemon with optional DNS config paths for bind mounting
  fn spawn_daemon(const std::vector<std::string> &daemonized_argv,
                  std::string_view resolv_conf_path = "",
                  std::string_view nsswitch_conf_path = "") -> error_or<pid_t>;

  fn execute(const std::vector<std::string> &argv) -> error_or<ok>;

  fn save() const -> error_or<ok>;
  fn load() -> error_or<ok>;

  fn sweep_orphans() -> error_or<ok>;

  [[nodiscard]] fn get_daemon_pid() const -> pid_t { return m_daemon_pid; }
  fn set_daemon_pid(pid_t pid) -> void { m_daemon_pid = pid; }

  [[nodiscard]] fn get_daemon_start_time() const -> u64
  {
    return m_daemon_start_time;
  }
  fn set_daemon_start_time(u64 s) -> void { m_daemon_start_time = s; }

private:
  linux_namespace &m_ns;
  pid_t m_daemon_pid{0};
  pid_t m_child_pid{0};
  u64 m_daemon_start_time{0};

  fn enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok>;

  static constexpr const char *PID_FILE = "pids.ini";
  static constexpr const char *STDOUT_LOG = "stdout";
  static constexpr const char *STDERR_LOG = "stderr";
};

} // namespace oo
