#pragma once

#include "cli.hh"
#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "proxy.hh"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

namespace oo {

class passwd;

class satan {
public:
  satan(linux_namespace &ns, passwd &pw) : m_ns(ns), m_pw(pw) {}

  // Spawn daemon with optional DNS config paths for bind mounting.
  // `start_cwd` is the absolute directory the daemon will chdir into just
  // before execvp; see comments in spawn_daemon for why this is separate
  // from the internal ns.get_path() chdir.
  // When `dns_on_monitor` is true the DNS config is bind mounted in the
  // monitor process's mount ns instead of the daemon's, so the daemon runs
  // with the host resolv.conf while `oo exec` commands still pick up the
  // configured DNS.
  fn spawn_daemon(const std::vector<std::string> &daemonized_argv,
                  std::string_view start_cwd,
                  std::string_view resolv_conf_path = "",
                  std::string_view nsswitch_conf_path = "",
                  bool dns_on_monitor = false) -> error_or<pid_t>;

  // `start_cwd` is the absolute directory the command will chdir into
  // inside the namespace's mount ns, just before execvp.
  [[nodiscard]] fn execute(const std::vector<std::string> &argv,
                           std::string_view start_cwd) -> error_or<ok>;

  // Spawn a forward proxy inside the namespace, bound to `bind`. Requires the
  // daemon to already be up so its net and mount namespaces can be joined. The
  // returned PID is the proxy process; it is persisted so `down` can stop it.
  // `reachable_ip` is the namespace IP the proxy is reachable at from the host.
  // It is shown in the process name so the usable listen address can be copied
  // straight from a process list, since the actual bind is 0.0.0.0.
  // `default_route` is the host interface the namespace NATs out through,
  // shown in the process name so a process list ties the proxy to its egress.
  [[nodiscard]] fn spawn_proxy(const endpoint &bind, proxy_backend_kind kind,
                               std::string_view reachable_ip,
                               std::string_view default_route)
      -> error_or<pid_t>;

  [[nodiscard]] fn save() const -> error_or<ok>;
  [[nodiscard]] fn load() -> error_or<ok>;

  [[nodiscard]] fn sweep_orphans() -> error_or<ok>;

  [[nodiscard]] fn get_daemon_pid() const -> pid_t { return m_daemon_pid; }
  fn set_daemon_pid(pid_t pid) -> void { m_daemon_pid = pid; }

  [[nodiscard]] fn get_daemon_start_time() const -> u64 {
    return m_daemon_start_time;
  }
  fn set_daemon_start_time(u64 s) -> void { m_daemon_start_time = s; }

  [[nodiscard]] fn get_dns_on_monitor() const -> bool {
    return m_dns_on_monitor;
  }
  fn set_dns_on_monitor(bool v) -> void { m_dns_on_monitor = v; }

  [[nodiscard]] fn get_proxy_pid() const -> pid_t { return m_proxy_pid; }
  fn set_proxy_pid(pid_t pid) -> void { m_proxy_pid = pid; }

  [[nodiscard]] fn get_proxy_start_time() const -> u64 {
    return m_proxy_start_time;
  }
  fn set_proxy_start_time(u64 s) -> void { m_proxy_start_time = s; }

  [[nodiscard]] fn get_proxy_backend() const -> proxy_backend_kind {
    return m_proxy_backend;
  }
  fn set_proxy_backend(proxy_backend_kind k) -> void { m_proxy_backend = k; }

  [[nodiscard]] fn get_creator_uid() const -> uid_t { return m_creator_uid; }
  fn set_creator_uid(uid_t uid) -> void { m_creator_uid = uid; }

  // Root always passes. A normal user passes only when their uid matches the
  // recorded creator. Namespaces created before ownership tracking carry the
  // unknown sentinel, which matches no real user, so they are root-only.
  [[nodiscard]] fn is_accessible_by(uid_t invoking_uid) const -> bool {
    return invoking_uid == 0 || invoking_uid == m_creator_uid;
  }

private:
  linux_namespace &m_ns;
  passwd &m_pw;
  pid_t m_daemon_pid{0};
  pid_t m_child_pid{0};
  u64 m_daemon_start_time{0};
  bool m_dns_on_monitor{false};
  pid_t m_proxy_pid{0};
  u64 m_proxy_start_time{0};
  proxy_backend_kind m_proxy_backend{proxy_backend_kind::builtin};
  uid_t m_creator_uid{static_cast<uid_t>(-1)};

  fn enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok>;

  static constexpr const char *PID_FILE = "pids.ini";
  static constexpr const char *STDOUT_LOG = "stdout";
  static constexpr const char *STDERR_LOG = "stderr";
};

} // namespace oo
