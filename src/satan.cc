#include "satan.hh"
#include "debug.hh"
#include "mountain.hh"
#include "netlinker.hh"
#include "pid_tracker.hh"

#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <sched.h>
#include <sstream>
#include <sys/wait.h>

namespace oo {

fn satan::spawn_daemon(const std::vector<std::string> &daemonized_argv,
                       std::string_view resolv_conf_path,
                       std::string_view nsswitch_conf_path) -> error_or<pid_t> {
  trace(verbosity::info, "Spawning daemon for namespace '{}'", m_ns.get_name());
  unwrap(m_ns.create_dir());

  int pipes[2];
  trace(verbosity::debug, "Creating pipe for daemon communication");
  unwrap(oo_linux_syscall(pipe, pipes));

  trace(verbosity::debug, "Forking parent process");
  let child_pid = unwrap(oo_linux_syscall(fork));

  let start_daemon = [&daemonized_argv, resolv_conf_path, nsswitch_conf_path](
                         linux_namespace &ns) -> error_or<pid_t> {
    unwrap(ns.unshare());
    trace(verbosity::debug, "Creating new session");
    unwrap(oo_linux_syscall(setsid));

    trace(verbosity::debug, "Setting umask and changing directory");
    unwrap(oo_linux_syscall(umask, 0));
    unwrap(oo_linux_syscall(chdir, unwrap(ns.get_path()).c_str()));

    trace(verbosity::debug, "Forking daemon process");
    let child_pid = unwrap(oo_linux_syscall(fork));
    if (child_pid != 0) {
      trace(verbosity::debug, "Monitoring process created, daemon PID: {}",
            child_pid);
      return child_pid;
    }

    trace(verbosity::debug, "Unsharing mount namespace");
    unwrap(oo_linux_syscall(unshare, CLONE_NEWNS));

    if (!resolv_conf_path.empty() || !nsswitch_conf_path.empty()) {
      mountain mnt(ns);
      unwrap(mnt.make_root_private());

      if (!resolv_conf_path.empty()) {
        trace(verbosity::debug, "Bind mounting resolv.conf");
        unwrap(mnt.bind_mount(resolv_conf_path, "/etc/resolv.conf"));
      }

      if (!nsswitch_conf_path.empty()) {
        trace(verbosity::debug, "Bind mounting nsswitch.conf");
        unwrap(mnt.bind_mount(nsswitch_conf_path, "/etc/nsswitch.conf"));
      }
    }

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

    unwrap(linux::oo_close(pipes[0]));
    let ret = start_daemon(m_ns);
    if (ret.is_err()) {
      let err_text = ret.get_error().get_owned_reason();
      unused(oo_linux_syscall(write, pipes[1], "err\n", 4));
      unused(oo_linux_syscall(write, pipes[1], err_text.data(),
                              err_text.length()));
      unwrap(linux::oo_close(pipes[1]));
      exit(EXIT_FAILURE);
    }

    let daemon_pid = ret.get_value();
    let ok_msg = "ok:" + std::to_string(daemon_pid) + "\n";
    unused(oo_linux_syscall(write, pipes[1], ok_msg.data(), ok_msg.length()));
    unwrap(linux::oo_close(pipes[1]));

    int status;
    let wait_result = oo_linux_syscall(waitpid, daemon_pid, &status, 0);
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

  unwrap(linux::oo_close(pipes[1]));

  struct pollfd daemon_log = {.fd = pipes[0], .events = POLLIN, .revents = 0};
  let ret = unwrap(oo_linux_syscall(poll, &daemon_log, 1, 5 * 1000));
  insist(ret >= 0);

  if (ret == 0) {
    return make_error("`poll()` timed out. No daemon was started.");
  }

  char buf[4096];
  let n = unwrap(oo_linux_syscall(read, pipes[0], buf, sizeof(buf) - 1));
  unwrap(linux::oo_close(pipes[0]));

  buf[n] = '\0';
  std::string_view msg(buf, n);

  if (msg.starts_with("err\n")) {
    std::string err_msg = "Daemon process failed";
    if (msg.length() > 4) {
      err_msg += ": " + std::string{msg.substr(4)};
    }
    return make_error(err_msg);
  }

  insist(msg.starts_with("ok:"));
  m_child_pid = std::stoi(std::string{msg.substr(3)});

  trace(verbosity::info, "Daemon spawned successfully, PID: {}", child_pid);

  return child_pid;
}

fn satan::enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok> {
  trace_variables(verbosity::debug, daemon_pid, inner_pid);
  let net_ns_path = "/proc/" + std::to_string(daemon_pid) + "/ns/net";
  int net_fd = unwrap(linux::oo_open(net_ns_path.c_str(), O_RDONLY));
  defer { unused(linux::oo_close(net_fd)); };

  // inner_pid unshared CLONE_NEWNS and applied bind mounts; daemon_pid did not.
  let mnt_pid = inner_pid != 0 ? inner_pid : daemon_pid;
  let mnt_ns_path = "/proc/" + std::to_string(mnt_pid) + "/ns/mnt";
  int mnt_fd = unwrap(linux::oo_open(mnt_ns_path.c_str(), O_RDONLY));
  defer { unused(linux::oo_close(mnt_fd)); };

  unwrap(oo_linux_syscall(setns, net_fd, CLONE_NEWNET));
  trace(verbosity::debug, "Entered network namespace");

  unwrap(oo_linux_syscall(setns, mnt_fd, CLONE_NEWNS));
  trace(verbosity::debug, "Entered mount namespace");

  return ok{};
}

fn satan::save() const -> error_or<ok> {
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  std::ofstream file(pid_path);
  if (!file.is_open()) {
    return make_error("Could not open PID file for writing: " +
                      pid_path.string());
  }

  file << "# Process state\n";
  file << "daemon_pid=" << m_daemon_pid << "\n";
  file << "child_pid=" << m_child_pid << "\n";

  if (!file.good()) {
    return make_error("Error writing to PID file");
  }

  trace(verbosity::debug, "Saved process state to {}", pid_path.string());
  return ok{};
}

fn satan::load() -> error_or<ok> {
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  std::ifstream file(pid_path);
  if (!file.is_open()) {
    return make_error("Could not open PID file: " + pid_path.string());
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    let eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    std::string key = line.substr(0, eq_pos);
    std::string value = line.substr(eq_pos + 1);

    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);

    if (key == "daemon_pid") {
      m_daemon_pid = std::stoi(value);
    } else if (key == "child_pid") {
      m_child_pid = std::stoi(value);
    }
  }

  trace(verbosity::debug, "Loaded process state from {}", pid_path.string());
  return ok{};
}

fn satan::execute(const std::vector<std::string> &argv) -> error_or<ok> {
  unwrap(load());

  if (m_daemon_pid == 0) {
    return make_error("No daemon running in namespace '" + m_ns.get_name() +
                      "'");
  }

  if (!pid_tracker::is_alive(m_daemon_pid)) {
    trace(verbosity::error,
          "Daemon is not running (stale PID {}). Cleaning up...", m_daemon_pid);

    return make_error("Daemon is not running in namespace '" + m_ns.get_name() +
                      "'");
  }

  trace(verbosity::info, "Entering namespace '{}' (daemon PID: {})",
        m_ns.get_name(), m_daemon_pid);

  unwrap(enter_namespace(m_daemon_pid, m_child_pid));

  trace(verbosity::info, "Executing: {}", argv[0]);
  unwrap(linux::oo_exec(argv));

  unreachable();
}

} // namespace oo
