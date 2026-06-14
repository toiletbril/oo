#include "satan.hh"

#include "caps.hh"
#include "constants.hh"
#include "debug.hh"
#include "ini.hh"
#include "linux_util.hh"
#include "mountain.hh"
#include "netlinker.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"
#include "proxy.hh"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <sched.h>
#include <sys/wait.h>

namespace oo {

namespace {
// Parse an unsigned decimal field read from a state file or the daemon status
// pipe. The build runs with -fno-exceptions, so std::stoull on a corrupt value
// would terminate the process. This returns an error instead, which lets load()
// and the spawn handshake fail cleanly on a truncated or garbled file.
fn parse_u64_field(std::string_view name, const std::string &value)
    -> error_or<u64> {
  char *end = nullptr;
  errno = 0;
  unsigned long long parsed = strtoull(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != '\0' || errno != 0) {
    return make_error("Corrupt value '" + value + "' for '" +
                      std::string{name} + "' in the state file");
  }
  return static_cast<u64>(parsed);
}
} // namespace

fn satan::spawn_daemon(const std::vector<std::string> &daemonized_argv,
                       std::string_view start_cwd,
                       std::string_view resolv_conf_path,
                       std::string_view nsswitch_conf_path, bool dns_on_monitor)
    -> error_or<pid_t> {
  insist(!daemonized_argv.empty(),
         "spawn_daemon requires at least one argv element for execvp");
  insist(!daemonized_argv[0].empty(),
         "daemonized_argv[0] must be the program path");
  insist(!start_cwd.empty() && start_cwd.front() == '/',
         "start_cwd must be a non-empty absolute path");
  trace_self(verbosity::debug);
  trace(verbosity::info, "Spawning daemon for namespace '{}'", m_ns.get_name());
  unwrap(m_ns.create_dir());

  trace(verbosity::debug, "Creating pipe for daemon communication");
  let[pipe_rd, pipe_wr] = unwrap(linux::oo_pipe());

  // Second pipe carrying the daemon's exec outcome to the monitor. Its write
  // end lives only in the daemon and is close-on-exec, so a successful exec
  // closes it with no bytes and the monitor reads EOF. A failure before exec
  // writes its reason here instead, before the daemon exits. The monitor sends
  // its own OK to the caller only after this confirms exec, so the caller never
  // sees success for a daemon that died on the way to exec.
  let[exec_rd, exec_wr] = unwrap(linux::oo_pipe());

  trace(verbosity::debug, "Forking parent process");
  let child_pid = unwrap(linux::oo_fork());

  let start_daemon = [this, &daemonized_argv, start_cwd, resolv_conf_path,
                      nsswitch_conf_path, dns_on_monitor, &exec_rd,
                      &exec_wr](linux_namespace &ns) -> error_or<pid_t> {
    unwrap(ns.unshare());
    trace(verbosity::debug, "Creating new session");
    unwrap(linux::oo_setsid());

    trace(verbosity::debug, "Setting umask and changing directory");
    unwrap(oo_linux_syscall(umask, 0));
    let expected_cwd = unwrap(ns.get_path());
    unwrap(linux::oo_chdir(expected_cwd.c_str()));
    char actual_cwd[PATH_MAX];
    insist(::getcwd(actual_cwd, sizeof(actual_cwd)) != nullptr,
           "getcwd failed after chdir to namespace directory");
    std::error_code cwd_ec;
    insist(std::filesystem::equivalent(expected_cwd, actual_cwd, cwd_ec),
           "chdir returned success but cwd is not the namespace directory");

    trace(verbosity::debug, "Forking daemon process");
    let child_pid = unwrap(linux::oo_fork());
    if (child_pid != 0) {
      // The monitor only reads the exec outcome. Closing its write end leaves
      // the daemon as the sole writer, so the read can reach EOF on exec.
      exec_wr.reset(-1);
      trace(verbosity::debug, "Monitoring process created, daemon PID: {}",
            child_pid);
      return child_pid;
    }

    // The daemon only reports through its write end, so drop the read end.
    exec_rd.reset(-1);
    linux::set_process_name("oo: daemon [" + ns.get_name() + "]");

    // With dns_on_monitor the daemon keeps the host's /etc/resolv.conf. The
    // monitor process applies the bind mounts in its own mount ns instead,
    // so it does not unshare CLONE_NEWNS here either.
    if (!dns_on_monitor) {
      trace(verbosity::debug, "Unsharing mount namespace");
      unwrap(linux::oo_unshare(CLONE_NEWNS));

      if (!resolv_conf_path.empty() || !nsswitch_conf_path.empty()) {
        mountain mnt(ns);
        unwrap(mnt.make_root_private());

        if (!resolv_conf_path.empty()) {
          trace(verbosity::debug, "Bind mounting resolv.conf");
          unwrap(mnt.bind_mount(std::string{resolv_conf_path},
                                std::string{"/etc/resolv.conf"}));
        }

        if (!nsswitch_conf_path.empty()) {
          trace(verbosity::debug, "Bind mounting nsswitch.conf");
          unwrap(mnt.bind_mount(std::string{nsswitch_conf_path},
                                std::string{"/etc/nsswitch.conf"}));
        }
      }
    }

    if (let log_dir = ns.get_path(); !log_dir.is_err()) {
      const std::string out_path =
          (log_dir.get_value() / satan::STDOUT_LOG).string();
      const std::string err_path =
          (log_dir.get_value() / satan::STDERR_LOG).string();
      linux::oo_fd out_fd{::open(
          out_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644)};
      if (out_fd.is_valid()) {
        unused(linux::oo_dup2(out_fd, STDOUT_FILENO));
      }
      linux::oo_fd err_fd{::open(
          err_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644)};
      if (err_fd.is_valid()) {
        unused(linux::oo_dup2(err_fd, STDERR_FILENO));
      }
    }

    // SECURITY: Drop back to the invoking user before the final exec so
    // the daemon process is owned by the human who ran `oo up`, not by
    // the oorunner system account. The log files opened above were
    // created while we were still oorunner, so they end up
    // oorunner-owned 0644 -- readable by the invoking user.
    unwrap(m_pw.su());

    // SECURITY: Drop all capabilities before exec so the daemon process
    // starts with no elevated privileges. The daemon runs inside the
    // network namespace and needs no special capabilities.
    unwrap(caps::drop_all_caps());

    // Land the daemon in the caller's chosen directory. chdir runs as the
    // invoking user (m_pw.su() above), so the check is the caller's own
    // x-permission on start_cwd, not oorunner's.
    trace(verbosity::debug, "Changing daemon cwd to {}",
          std::string{start_cwd});
    unwrap(linux::oo_chdir(std::string{start_cwd}.c_str()));

    trace(verbosity::debug, "Executing daemon: {}", daemonized_argv[0]);
    unwrap(linux::oo_exec(daemonized_argv));
    unreachable();
  };

  if (child_pid == 0) {
    struct sigaction sa{};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    unused(oo_linux_syscall(sigaction, SIGTERM, &sa, nullptr));
    unused(oo_linux_syscall(sigaction, SIGINT, &sa, nullptr));
    unused(oo_linux_syscall(sigaction, SIGHUP, &sa, nullptr));

    pipe_rd.reset(-1);
    let ret = start_daemon(m_ns);
    if (ret.is_err()) {
      // This runs in the daemon process, since start_daemon execs on success
      // and never returns here. Report the pre-exec failure to the monitor
      // through the exec pipe, which the monitor forwards to the caller.
      let err_text = ret.get_error().get_owned_reason();
      unused(linux::oo_write(exec_wr, err_text.data(), err_text.length()));
      exec_wr.reset(-1);
      exit(EXIT_FAILURE);
    }

    insist(!ret.is_err(), "daemon_pid extraction requires the success branch");
    let daemon_pid = ret.get_value();
    insist(daemon_pid > 0, "start_daemon must return a valid child PID");

    // Name the monitor only now that the daemon pid is known, so a process
    // list ties this reaper to the daemon it supervises.
    linux::set_process_name("oo: supervisor for daemon process " +
                            std::to_string(daemon_pid));

    // The daemon was forked before this point, so it does not inherit the
    // mount ns set up here. Bind the DNS config in the monitor's own mount
    // ns so `oo exec` (which joins the monitor's mnt ns) resolves through
    // it while the daemon keeps the host resolv.conf. Done while still
    // privileged, before the su()/drop below.
    if (dns_on_monitor) {
      let setup = [&]() -> error_or<ok> {
        unwrap(linux::oo_unshare(CLONE_NEWNS));
        if (!resolv_conf_path.empty() || !nsswitch_conf_path.empty()) {
          mountain mnt(m_ns);
          unwrap(mnt.make_root_private());
          if (!resolv_conf_path.empty()) {
            unwrap(mnt.bind_mount(std::string{resolv_conf_path},
                                  std::string{"/etc/resolv.conf"}));
          }
          if (!nsswitch_conf_path.empty()) {
            unwrap(mnt.bind_mount(std::string{nsswitch_conf_path},
                                  std::string{"/etc/nsswitch.conf"}));
          }
        }
        return ok{};
      }();

      if (setup.is_err()) {
        let err_text = setup.get_error().get_owned_reason();
        unused(linux::oo_kill(daemon_pid, SIGKILL));
        unused(linux::oo_write(pipe_wr, constants::DAEMON_MSG_ERR.data(),
                               constants::DAEMON_MSG_ERR.size()));
        unused(linux::oo_write(pipe_wr, err_text.data(), err_text.length()));
        pipe_wr.reset(-1);
        exit(EXIT_FAILURE);
      }
    }

    // Confirm the daemon reached exec before reporting success to the caller.
    // Bytes on the exec pipe mean it failed beforehand, so forward the reason;
    // EOF means the close-on-exec write end vanished on a clean exec.
    {
      char exec_buf[4096];
      let exec_n = linux::oo_read(exec_rd, exec_buf, sizeof(exec_buf) - 1);
      exec_rd.reset(-1);
      if (exec_n.is_err() || exec_n.get_value() > 0) {
        std::string reason =
            exec_n.is_err()
                ? std::string{"daemon exec status could not be read"}
                : std::string{exec_buf, static_cast<usize>(exec_n.get_value())};
        unused(linux::oo_write(pipe_wr, constants::DAEMON_MSG_ERR.data(),
                               constants::DAEMON_MSG_ERR.size()));
        unused(linux::oo_write(pipe_wr, reason.data(), reason.length()));
        pipe_wr.reset(-1);
        exit(EXIT_FAILURE);
      }
    }

    // SECURITY: Namespace setup is complete; monitoring process only waits.
    // Switch back to the invoking user so `ps` shows the monitor under
    // the human's uid (not oorunner), and clear caps so the reaper holds
    // no elevated privileges.
    unused(m_pw.su());
    unused(caps::drop_all_caps());

    let ok_msg = std::string{constants::DAEMON_MSG_OK} +
                 std::to_string(daemon_pid) + "\n";
    unused(linux::oo_write(pipe_wr, ok_msg.data(), ok_msg.length()));
    pipe_wr.reset(-1);

    int status;
    let wait_result = linux::oo_waitpid(daemon_pid, &status, 0);
    if (wait_result.is_err()) {
      exit(EXIT_FAILURE);
    }

    if (WIFEXITED(status)) {
      exit(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      exit(128 + WTERMSIG(status));
    }

    exit(EXIT_FAILURE);
  }

  pipe_wr.reset(-1);

  // The caller talks to the monitor only. Release its inherited copies of the
  // exec pipe so it does not hold the daemon's exec confirmation open, which
  // would keep the monitor from ever reading EOF on a clean exec.
  exec_rd.reset(-1);
  exec_wr.reset(-1);

  struct pollfd daemon_log = {
      .fd = pipe_rd.get(), .events = POLLIN, .revents = 0};
  let ret = unwrap(oo_linux_syscall(poll, &daemon_log, 1,
                                    constants::DAEMON_SPAWN_TIMEOUT_MS));
  insist(ret >= 0);

  if (ret == 0) {
    return make_error("`poll()` timed out. No daemon was started.");
  }

  char buf[4096];
  let n = unwrap(linux::oo_read(pipe_rd, buf, sizeof(buf) - 1));
  pipe_rd.reset(-1);

  insist(n >= 0 && static_cast<usize>(n) < sizeof(buf),
         "read returned out-of-range length for null-termination");
  buf[n] = '\0';
  const std::string_view msg(buf, n);

  if (msg.starts_with(constants::DAEMON_MSG_ERR)) {
    std::string err_msg = "Daemon process failed";
    if (msg.length() > 4) {
      err_msg += ": " + std::string{msg.substr(4)};
    }
    return make_error(err_msg);
  }

  insist(msg.starts_with(constants::DAEMON_MSG_OK));
  insist(msg.size() > constants::DAEMON_MSG_OK.size(),
         "DAEMON_MSG_OK prefix must be followed by a PID. Fuck you");
  std::string pid_str{msg.substr(constants::DAEMON_MSG_OK.size())};
  while (!pid_str.empty() &&
         (pid_str.back() == '\n' || pid_str.back() == '\r')) {
    pid_str.pop_back();
  }
  m_child_pid =
      static_cast<pid_t>(unwrap(parse_u64_field("daemon pid", pid_str)));

  trace(verbosity::info, "Daemon spawned successfully, PID: {}", child_pid);

  return child_pid;
}

fn satan::enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok> {
  trace_variables(verbosity::debug, daemon_pid, inner_pid);
  let net_ns_path = "/proc/" + std::to_string(daemon_pid) + "/ns/net";
  linux::oo_fd net_fd{unwrap(linux::oo_open(net_ns_path.c_str(), O_RDONLY))};

  // inner_pid unshared CLONE_NEWNS and applied bind mounts; daemon_pid did
  // not. With dns_on_monitor the binds live in the monitor's mount ns
  // (daemon_pid here), so join that one instead of the daemon's.
  let mnt_pid = m_dns_on_monitor ? daemon_pid
                : inner_pid != 0 ? inner_pid
                                 : daemon_pid;
  let mnt_ns_path = "/proc/" + std::to_string(mnt_pid) + "/ns/mnt";
  linux::oo_fd mnt_fd{unwrap(linux::oo_open(mnt_ns_path.c_str(), O_RDONLY))};

  unwrap(linux::oo_setns(net_fd, CLONE_NEWNET));
  {
    struct stat target{}, self{};
    unwrap(oo_linux_syscall(fstat, net_fd.get(), &target));
    unwrap(oo_linux_syscall(stat, "/proc/self/ns/net", &self));
    insist(target.st_ino == self.st_ino && target.st_dev == self.st_dev,
           "setns(CLONE_NEWNET) returned success but net ns did not change");
  }
  trace(verbosity::debug, "Entered network namespace");

  unwrap(linux::oo_setns(mnt_fd, CLONE_NEWNS));
  {
    struct stat target{}, self{};
    unwrap(oo_linux_syscall(fstat, mnt_fd.get(), &target));
    unwrap(oo_linux_syscall(stat, "/proc/self/ns/mnt", &self));
    insist(target.st_ino == self.st_ino && target.st_dev == self.st_dev,
           "setns(CLONE_NEWNS) returned success but mnt ns did not change");
  }
  trace(verbosity::debug, "Entered mount namespace");

  return ok{};
}

fn satan::spawn_proxy(const endpoint &bind, proxy_backend_kind kind,
                      std::string_view reachable_ip,
                      std::string_view default_route) -> error_or<pid_t> {
  insist(m_daemon_pid > 0, "spawn_proxy requires a known daemon PID");
  trace(verbosity::info, "Spawning proxy for namespace '{}'", m_ns.get_name());

  let pipe = unwrap(linux::oo_pipe());
  linux::oo_fd pipe_rd = std::move(pipe.first);
  linux::oo_fd pipe_wr = std::move(pipe.second);

  let child_pid = unwrap(linux::oo_fork());

  if (child_pid == 0) {
    struct sigaction sa{};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    unused(oo_linux_syscall(sigaction, SIGTERM, &sa, nullptr));
    unused(oo_linux_syscall(sigaction, SIGINT, &sa, nullptr));
    unused(oo_linux_syscall(sigaction, SIGHUP, &sa, nullptr));

    pipe_rd.reset(-1);

    let serve = [this, &bind, kind, reachable_ip, default_route,
                 &pipe_wr]() -> error_or<ok> {
      unwrap(linux::oo_setsid());

      if (let log_dir = m_ns.get_path(); !log_dir.is_err()) {
        const std::string out_path =
            (log_dir.get_value() / satan::STDOUT_LOG).string();
        const std::string err_path =
            (log_dir.get_value() / satan::STDERR_LOG).string();
        linux::oo_fd out_fd{::open(
            out_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644)};
        if (out_fd.is_valid()) {
          unused(linux::oo_dup2(out_fd, STDOUT_FILENO));
        }
        linux::oo_fd err_fd{::open(
            err_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644)};
        if (err_fd.is_valid()) {
          unused(linux::oo_dup2(err_fd, STDERR_FILENO));
        }
      }

      unwrap(enter_namespace(m_daemon_pid, m_child_pid));

      let p = make_proxy(kind, m_ns, m_daemon_pid);

      // Show the host-reachable namespace address rather than the 0.0.0.0 bind,
      // so the listen address can be copied straight from the process list.
      const std::string listen_addr =
          reachable_ip.empty()
              ? bind.to_string()
              : std::string{reachable_ip} + ":" + std::to_string(bind.port);
      const std::string route =
          default_route.empty() ? "unknown" : std::string{default_route};
      linux::set_process_name("oo: namespace http proxy " + listen_addr +
                              " for default route " + route);

      // Bind while still privileged so any port works and a bind failure is
      // reported to the parent before privileges are dropped.
      unwrap(p->prepare(bind));

      let ok_msg = std::string{constants::DAEMON_MSG_OK} +
                   std::to_string(getpid()) + "\n";
      unused(linux::oo_write(pipe_wr, ok_msg.data(), ok_msg.length()));
      pipe_wr.reset(-1);

      // SECURITY: drop to the invoking user and clear capabilities before the
      // proxy starts serving. The listening socket was already created above
      // and survives the credential change.
      unwrap(m_pw.su());
      unwrap(caps::drop_all_caps());

      unwrap(p->run());
      unreachable();
    };

    let ret = serve();
    insist(ret.is_err(), "serve() must only return on error");
    let err_text = ret.get_error().get_owned_reason();
    unused(linux::oo_write(pipe_wr, constants::DAEMON_MSG_ERR.data(),
                           constants::DAEMON_MSG_ERR.size()));
    unused(linux::oo_write(pipe_wr, err_text.data(), err_text.length()));
    pipe_wr.reset(-1);
    exit(EXIT_FAILURE);
  }

  pipe_wr.reset(-1);

  struct pollfd proxy_log = {
      .fd = pipe_rd.get(), .events = POLLIN, .revents = 0};
  let ret = unwrap(oo_linux_syscall(poll, &proxy_log, 1,
                                    constants::DAEMON_SPAWN_TIMEOUT_MS));
  insist(ret >= 0);

  if (ret == 0) {
    unused(linux::oo_kill(child_pid, SIGKILL));
    return make_error("`poll()` timed out. No proxy was started.");
  }

  char buf[4096];
  let n = unwrap(linux::oo_read(pipe_rd, buf, sizeof(buf) - 1));
  pipe_rd.reset(-1);

  insist(n >= 0 && static_cast<usize>(n) < sizeof(buf),
         "read returned out-of-range length for null-termination");
  buf[n] = '\0';
  const std::string_view msg(buf, n);

  if (msg.starts_with(constants::DAEMON_MSG_ERR)) {
    std::string err_msg = "Proxy process failed";
    if (msg.length() > constants::DAEMON_MSG_ERR.size()) {
      err_msg +=
          ": " + std::string{msg.substr(constants::DAEMON_MSG_ERR.size())};
    }
    unused(linux::oo_kill(child_pid, SIGKILL));
    return make_error(err_msg);
  }

  insist(msg.starts_with(constants::DAEMON_MSG_OK));
  trace(verbosity::info, "Proxy spawned successfully, PID: {}", child_pid);

  return child_pid;
}

fn satan::save() const -> error_or<ok> {
  trace_self(verbosity::debug);
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  ini_file file{pid_path};
  unwrap(file.load());
  insist(m_daemon_pid >= 0 && m_child_pid >= 0 && m_proxy_pid >= 0,
         "satan::save must not persist negative PIDs");
  file.set_header("Process state");
  file.set("daemon_pid", std::to_string(m_daemon_pid));
  file.set("child_pid", std::to_string(m_child_pid));
  file.set("daemon_start_time", std::to_string(m_daemon_start_time));
  file.set("dns_on_monitor", m_dns_on_monitor ? "1" : "0");
  file.set("proxy_pid", std::to_string(m_proxy_pid));
  file.set("proxy_start_time", std::to_string(m_proxy_start_time));
  file.set("proxy_backend",
           m_proxy_backend == proxy_backend_kind::squid ? "squid" : "builtin");
  file.set("creator_uid", std::to_string(m_creator_uid));
  unwrap(file.flush());

  trace(verbosity::debug, "Saved process state to {}", pid_path.string());

  return ok{};
}

fn satan::load() -> error_or<ok> {
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  std::error_code ec;
  if (!std::filesystem::exists(pid_path, ec)) {
    unwrap(oo_error_code(ec, "Could not stat PID file " + pid_path.string()));
    return make_error("The PID file '" + pid_path.string() +
                      "' does not exist");
  }

  ini_file file{pid_path};
  unwrap(file.load());

  if (let v = file.find("daemon_pid")) {
    insist(!v->empty(), "daemon_pid entry must have a non-empty value");
    m_daemon_pid =
        static_cast<pid_t>(unwrap(parse_u64_field("daemon_pid", *v)));
  }
  if (let v = file.find("child_pid")) {
    insist(!v->empty(), "child_pid entry must have a non-empty value");
    m_child_pid = static_cast<pid_t>(unwrap(parse_u64_field("child_pid", *v)));
  }
  if (let v = file.find("daemon_start_time")) {
    insist(!v->empty(), "daemon_start_time entry must have a non-empty value");
    m_daemon_start_time = unwrap(parse_u64_field("daemon_start_time", *v));
  }
  if (let v = file.find("dns_on_monitor")) {
    insist(!v->empty(), "dns_on_monitor entry must have a non-empty value");
    m_dns_on_monitor = (*v == "1");
  }
  if (let v = file.find("proxy_pid")) {
    insist(!v->empty(), "proxy_pid entry must have a non-empty value");
    m_proxy_pid = static_cast<pid_t>(unwrap(parse_u64_field("proxy_pid", *v)));
  }
  if (let v = file.find("proxy_start_time")) {
    insist(!v->empty(), "proxy_start_time entry must have a non-empty value");
    m_proxy_start_time = unwrap(parse_u64_field("proxy_start_time", *v));
  }
  if (let v = file.find("proxy_backend")) {
    // Default to builtin on a missing or unrecognized value rather than failing
    // the load, since the backend is only used for reporting.
    if (let b = parse_proxy_backend(*v); !b.is_err()) {
      m_proxy_backend = b.get_value();
    }
  }
  if (let v = file.find("creator_uid")) {
    insist(!v->empty(), "creator_uid entry must have a non-empty value");
    m_creator_uid =
        static_cast<uid_t>(unwrap(parse_u64_field("creator_uid", *v)));
  }

  trace(verbosity::debug, "Loaded process state from {}", pid_path.string());

  return ok{};
}

fn satan::sweep_orphans() -> error_or<ok> {
  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec) || ec) {
    return ok{};
  }

  for (let &entry :
       std::filesystem::directory_iterator(constants::OO_RUN_DIR, ec)) {
    if (ec) {
      trace(verbosity::error, "Failed to enumerate {}: {}",
            constants::OO_RUN_DIR, ec.message());
      return ok{};
    }
    if (!entry.is_directory(ec) || ec) {
      continue;
    }

    const std::string name = entry.path().filename().string();
    linux_namespace probe_ns{name};
    satan probe{probe_ns, m_pw};

    // Skip namespace directories that exist but have no pids.ini. Such a
    // dir is either being created by a concurrent up or touch between
    // create_dir and save, or it is leftover from a setup that crashed
    // before the first save. The concurrent-setup case must not be moved
    // out from under the other process, and the crash case is already
    // caught when the user runs `oo up` on the same name, which refuses
    // to adopt a dir with no oo state.
    std::error_code pf_ec;
    if (!std::filesystem::exists(entry.path() / PID_FILE, pf_ec) || pf_ec) {
      continue;
    }

    bool orphan = false;
    if (probe.load().is_err()) {
      orphan = true;
    } else if (!pid_tracker::is_alive_with_start_time(
                   probe.get_daemon_pid(), probe.get_daemon_start_time())) {
      orphan = true;
    }

    if (!orphan) {
      continue;
    }

    // Only the owner, or root, reaps an orphan. This stops one user's sweep,
    // triggered by an unrelated up or down, from moving another user's stale
    // namespace out from under them. A namespace whose state did not load has
    // no recorded owner, so a non-root sweeper leaves it for root.
    if (!probe.is_accessible_by(m_pw.get_invoking_uid())) {
      continue;
    }

    // Best effort: stop a proxy left behind by a dead daemon. This only
    // succeeds when the sweeping process shares the proxy's uid, which is the
    // case on the `down` path where the invoking user owns both.
    if (probe.get_proxy_pid() > 0 &&
        pid_tracker::is_alive_with_start_time(probe.get_proxy_pid(),
                                              probe.get_proxy_start_time())) {
      unused(linux::oo_kill(probe.get_proxy_pid(), SIGKILL));
    }

    let now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
    const std::filesystem::path target =
        std::filesystem::path{"/tmp"} /
        ("oo-orphan-" + name + "-" + std::to_string(now_ms));

    // SECURITY: never follow a symlink at the /tmp target. Another user
    // may have planted one pointing at a sensitive path; touching it would
    // let orphan cleanup be weaponized into an out-of-tree write.
    std::error_code stat_ec;
    let target_status = std::filesystem::symlink_status(target, stat_ec);
    if (!stat_ec &&
        target_status.type() == std::filesystem::file_type::symlink) {
      return make_error("Refusing to clean orphan '" + name +
                        "' because its target '" + target.string() +
                        "' is a symlink");
    }

    if (!stat_ec && std::filesystem::exists(target_status)) {
      // Target already occupied -- cannot move in safely. Just drop the
      // orphan namespace directory.
      std::error_code rm_ec;
      std::filesystem::remove_all(entry.path(), rm_ec);
      if (rm_ec) {
        trace(verbosity::error, "Failed to remove orphan namespace '{}': {}",
              name, rm_ec.message());
        continue;
      }
      trace(verbosity::info,
            "Removed orphan namespace '{}' ({} already exists)", name,
            target.string());
      continue;
    }

    std::error_code rename_ec;
    std::filesystem::rename(entry.path(), target, rename_ec);
    if (rename_ec == std::errc::cross_device_link) {
      // /var/run/oo and /tmp are usually different tmpfs mounts; fall back
      // to recursive copy then delete the source. Same end state, slower.
      std::error_code copy_ec;
      std::filesystem::copy(entry.path(), target,
                            std::filesystem::copy_options::recursive, copy_ec);
      if (copy_ec) {
        trace(verbosity::error,
              "Failed to copy orphan namespace '{}' to {}: {}", name,
              target.string(), copy_ec.message());
        continue;
      }
      std::filesystem::remove_all(entry.path(), copy_ec);
      if (copy_ec) {
        trace(verbosity::error, "Failed to remove orphan source {}: {}",
              entry.path().string(), copy_ec.message());
        continue;
      }
    } else if (rename_ec) {
      trace(verbosity::error, "Failed to move orphan namespace '{}' to {}: {}",
            name, target.string(), rename_ec.message());
      continue;
    }

    trace(verbosity::info, "Moved orphan namespace '{}' to {}", name,
          target.string());
  }

  return ok{};
}

fn satan::execute(const std::vector<std::string> &argv,
                  std::string_view start_cwd) -> error_or<ok> {
  insist(!argv.empty(), "satan::execute requires at least one argv element");
  insist(!argv[0].empty(), "argv[0] must be the program path for execvp");
  insist(!start_cwd.empty() && start_cwd.front() == '/',
         "start_cwd must be a non-empty absolute path");
  trace_self(verbosity::debug);

  if (let r = load(); r.is_err()) {
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  if (!is_accessible_by(m_pw.get_invoking_uid())) {
    return make_error("Namespace '" + m_ns.get_name() +
                      "' is owned by another user");
  }

  if (m_daemon_pid == 0) {
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  if (!pid_tracker::is_alive_with_start_time(m_daemon_pid,
                                             m_daemon_start_time)) {
    trace(verbosity::error, "Daemon has stale PID {}.", m_daemon_pid);
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  trace(verbosity::info, "Entering namespace '{}' (daemon PID: {})",
        m_ns.get_name(), m_daemon_pid);

  unwrap(enter_namespace(m_daemon_pid, m_child_pid));

  // SECURITY: Drop back to the invoking user before the final exec so
  // the command runs under the user's uid, not oorunner.
  unwrap(m_pw.su());

  // SECURITY: Drop all capabilities before exec. setns() (enter_namespace)
  // already ran in this process using its file capabilities. The exec'd
  // command runs inside the namespace and needs no elevated privileges.
  unwrap(caps::drop_all_caps());

  // Land the command in the caller's cwd inside the namespace's mount ns.
  // The path is resolved in the new mount ns; if it is not reachable
  // there the chdir fails and the user sees the error.
  trace(verbosity::debug, "Changing cwd to {}", std::string{start_cwd});
  unwrap(linux::oo_chdir(std::string{start_cwd}.c_str()));

  trace(verbosity::info, "Executing: {}", argv[0]);
  unwrap(linux::oo_exec(argv));

  unreachable();
}

} // namespace oo
