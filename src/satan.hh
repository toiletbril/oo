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

class passwd;

class satan
{
public:
  satan(linux_namespace &ns, passwd &pw) : m_ns(ns), m_pw(pw) {}

  // Spawn daemon with optional DNS config paths for bind mounting.
  // `start_cwd` is the absolute directory the daemon will chdir into just
  // before execvp; see comments in spawn_daemon for why this is separate
  // from the internal ns.get_path() chdir.
  fn spawn_daemon(const std::vector<std::string> &daemonized_argv,
                  std::string_view start_cwd,
                  std::string_view resolv_conf_path = "",
                  std::string_view nsswitch_conf_path = "") -> error_or<pid_t>;

  // `start_cwd` is the absolute directory the command will chdir into
  // inside the namespace's mount ns, just before execvp.
  fn execute(const std::vector<std::string> &argv, std::string_view start_cwd)
      -> error_or<ok>;

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
  passwd &m_pw;
  pid_t m_daemon_pid{0};
  pid_t m_child_pid{0};
  u64 m_daemon_start_time{0};

  fn enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok>;

  static constexpr const char *PID_FILE = "pids.ini";
  static constexpr const char *STDOUT_LOG = "stdout";
  static constexpr const char *STDERR_LOG = "stderr";
};

} // namespace oo
