#include "satan.hh"

#include "caps.hh"
#include "constants.hh"
#include "debug.hh"
#include "ini.hh"
#include "invoking_user.hh"
#include "linux_util.hh"
#include "mountain.hh"
#include "netlinker.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"

#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <sched.h>
#include <sys/wait.h>

namespace oo {

fn satan::spawn_daemon(const std::vector<std::string> &daemonized_argv,
                       std::string_view resolv_conf_path,
                       std::string_view nsswitch_conf_path) -> error_or<pid_t>
{
  insist(!daemonized_argv.empty(),
         "spawn_daemon requires at least one argv element for execvp");
  insist(!daemonized_argv[0].empty(),
         "daemonized_argv[0] must be the program path");
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
    let expected_cwd = unwrap(ns.get_path());
    unwrap(oo_linux_syscall(chdir, expected_cwd.c_str()));
    char actual_cwd[PATH_MAX];
    insist(::getcwd(actual_cwd, sizeof(actual_cwd)) != nullptr,
           "getcwd failed after chdir to namespace directory");
    std::error_code cwd_ec;
    insist(std::filesystem::equivalent(expected_cwd, actual_cwd, cwd_ec),
           "chdir returned success but cwd is not the namespace directory");

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
        unwrap(mnt.bind_mount(std::string{resolv_conf_path},
                              std::string{"/etc/resolv.conf"}));
      }

      if (!nsswitch_conf_path.empty()) {
        trace(verbosity::debug, "Bind mounting nsswitch.conf");
        unwrap(mnt.bind_mount(std::string{nsswitch_conf_path},
                              std::string{"/etc/nsswitch.conf"}));
      }
    }

    if (let log_dir = ns.get_path(); !log_dir.is_err()) {
      std::string out_path = (log_dir.get_value() / satan::STDOUT_LOG).string();
      std::string err_path = (log_dir.get_value() / satan::STDERR_LOG).string();
      int out_fd = ::open(out_path.c_str(),
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (out_fd >= 0) {
        ::dup2(out_fd, STDOUT_FILENO);
        ::close(out_fd);
      }
      int err_fd = ::open(err_path.c_str(),
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (err_fd >= 0) {
        ::dup2(err_fd, STDERR_FILENO);
        ::close(err_fd);
      }
    }

    // SECURITY: Drop back to the invoking user before the final exec so
    // the daemon process is owned by the human who ran `oo up`, not by
    // the oorunner system account. The log files opened above were
    // created while we were still oorunner, so they end up
    // oorunner-owned 0644 -- readable by the invoking user.
    unwrap(privilege_drop::switch_to_user(g_invoking_uid, g_invoking_gid));

    // SECURITY: Drop all capabilities before exec so the daemon process
    // starts with no elevated privileges. The daemon runs inside the
    // network namespace and needs no special capabilities.
    unwrap(caps::drop_for_exec());

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
      unused(oo_linux_syscall(write, pipes[1], constants::DAEMON_MSG_ERR.data(),
                              constants::DAEMON_MSG_ERR.size()));
      unused(oo_linux_syscall(write, pipes[1], err_text.data(),
                              err_text.length()));
      unwrap(linux::oo_close(pipes[1]));
      exit(EXIT_FAILURE);
    }

    insist(!ret.is_err(), "daemon_pid extraction requires the success branch");
    let daemon_pid = ret.get_value();
    insist(daemon_pid > 0, "start_daemon must return a valid child PID");

    // SECURITY: Namespace setup is complete; monitoring process only waits.
    // Switch back to the invoking user so `ps` shows the monitor under
    // the human's uid (not oorunner), and clear caps so the reaper holds
    // no elevated privileges.
    unused(privilege_drop::switch_to_user(g_invoking_uid, g_invoking_gid));
    unused(caps::drop_for_exec());

    let ok_msg = std::string{constants::DAEMON_MSG_OK} +
                 std::to_string(daemon_pid) + "\n";
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
  let ret = unwrap(oo_linux_syscall(poll, &daemon_log, 1,
                                    constants::DAEMON_SPAWN_TIMEOUT_MS));
  insist(ret >= 0);

  if (ret == 0) {
    return make_error("`poll()` timed out. No daemon was started.");
  }

  char buf[4096];
  let n = unwrap(oo_linux_syscall(read, pipes[0], buf, sizeof(buf) - 1));
  unwrap(linux::oo_close(pipes[0]));

  insist(n >= 0 && static_cast<usize>(n) < sizeof(buf),
         "read returned out-of-range length for null-termination");
  buf[n] = '\0';
  std::string_view msg(buf, n);

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
  m_child_pid =
      std::stoi(std::string{msg.substr(constants::DAEMON_MSG_OK.size())});

  trace(verbosity::info, "Daemon spawned successfully, PID: {}", child_pid);

  return child_pid;
}

fn satan::enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok>
{
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
  {
    struct stat target{}, self{};
    unwrap(oo_linux_syscall(fstat, net_fd, &target));
    unwrap(oo_linux_syscall(stat, "/proc/self/ns/net", &self));
    insist(target.st_ino == self.st_ino && target.st_dev == self.st_dev,
           "setns(CLONE_NEWNET) returned success but net ns did not change");
  }
  trace(verbosity::debug, "Entered network namespace");

  unwrap(oo_linux_syscall(setns, mnt_fd, CLONE_NEWNS));
  {
    struct stat target{}, self{};
    unwrap(oo_linux_syscall(fstat, mnt_fd, &target));
    unwrap(oo_linux_syscall(stat, "/proc/self/ns/mnt", &self));
    insist(target.st_ino == self.st_ino && target.st_dev == self.st_dev,
           "setns(CLONE_NEWNS) returned success but mnt ns did not change");
  }
  trace(verbosity::debug, "Entered mount namespace");

  return ok{};
}

fn satan::save() const -> error_or<ok>
{
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  ini_file file{pid_path};
  unwrap(file.load());
  insist(m_daemon_pid >= 0 && m_child_pid >= 0,
         "satan::save must not persist negative PIDs");
  file.set_header("Process state");
  file.set("daemon_pid", std::to_string(m_daemon_pid));
  file.set("child_pid", std::to_string(m_child_pid));
  file.set("daemon_start_time", std::to_string(m_daemon_start_time));
  unwrap(file.flush());

  trace(verbosity::debug, "Saved process state to {}", pid_path.string());
  return ok{};
}

fn satan::load() -> error_or<ok>
{
  let ns_path = unwrap(m_ns.get_path());
  let pid_path = ns_path / PID_FILE;

  std::error_code ec;
  if (!std::filesystem::exists(pid_path, ec)) {
    unwrap(oo_error_code(ec, "Could not stat PID file " + pid_path.string()));
    return make_error("PID file does not exist: " + pid_path.string());
  }

  ini_file file{pid_path};
  unwrap(file.load());

  if (let v = file.find("daemon_pid")) {
    insist(!v->empty(), "daemon_pid entry must have a non-empty value");
    m_daemon_pid = std::stoi(*v);
  }
  if (let v = file.find("child_pid")) {
    insist(!v->empty(), "child_pid entry must have a non-empty value");
    m_child_pid = std::stoi(*v);
  }
  if (let v = file.find("daemon_start_time")) {
    insist(!v->empty(), "daemon_start_time entry must have a non-empty value");
    m_daemon_start_time = std::stoull(*v);
  }

  trace(verbosity::debug, "Loaded process state from {}", pid_path.string());
  return ok{};
}

fn satan::execute(const std::vector<std::string> &argv) -> error_or<ok>
{
  insist(!argv.empty(), "satan::execute requires at least one argv element");
  insist(!argv[0].empty(), "argv[0] must be the program path for execvp");

  if (let r = load(); r.is_err()) {
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  if (m_daemon_pid == 0) {
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  if (!pid_tracker::is_alive_with_start_time(m_daemon_pid, m_daemon_start_time))
  {
    trace(verbosity::error, "Daemon has stale PID {}.", m_daemon_pid);
    return make_error("Namespace '" + m_ns.get_name() + "' is not running");
  }

  trace(verbosity::info, "Entering namespace '{}' (daemon PID: {})",
        m_ns.get_name(), m_daemon_pid);

  unwrap(enter_namespace(m_daemon_pid, m_child_pid));

  // SECURITY: Drop back to the invoking user before the final exec so
  // the command runs under the user's uid, not oorunner.
  unwrap(privilege_drop::switch_to_user(g_invoking_uid, g_invoking_gid));

  // SECURITY: Drop all capabilities before exec. setns() (enter_namespace)
  // already ran in this process using its file capabilities. The exec'd
  // command runs inside the namespace and needs no elevated privileges.
  unwrap(caps::drop_for_exec());

  trace(verbosity::info, "Executing: {}", argv[0]);
  unwrap(linux::oo_exec(argv));

  unreachable();
}

} // namespace oo
