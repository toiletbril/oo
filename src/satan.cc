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

#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <sched.h>
#include <sys/wait.h>

namespace oo {

uid_t INVOKING_UID = 0;
gid_t INVOKING_GID = 0;

fn satan::spawn_daemon(const std::vector<std::string> &daemonized_argv,
                       std::string_view resolv_conf_path,
                       std::string_view nsswitch_conf_path) -> error_or<pid_t>
{
  insist(!daemonized_argv.empty(),
         "spawn_daemon requires at least one argv element for execvp");
  insist(!daemonized_argv[0].empty(),
         "daemonized_argv[0] must be the program path");
  trace_self(verbosity::debug);
  trace(verbosity::info, "Spawning daemon for namespace '{}'", m_ns.get_name());
  unwrap(m_ns.create_dir());

  trace(verbosity::debug, "Creating pipe for daemon communication");
  let[pipe_rd, pipe_wr] = unwrap(linux::oo_pipe());

  trace(verbosity::debug, "Forking parent process");
  let child_pid = unwrap(linux::oo_fork());

  let start_daemon = [&daemonized_argv, resolv_conf_path, nsswitch_conf_path](
                         linux_namespace &ns) -> error_or<pid_t> {
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
      trace(verbosity::debug, "Monitoring process created, daemon PID: {}",
            child_pid);
      return child_pid;
    }

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
    unwrap(privilege_drop::switch_to_user(INVOKING_UID, INVOKING_GID));

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

    pipe_rd.reset(-1);
    let ret = start_daemon(m_ns);
    if (ret.is_err()) {
      let err_text = ret.get_error().get_owned_reason();
      unused(linux::oo_write(pipe_wr, constants::DAEMON_MSG_ERR.data(),
                             constants::DAEMON_MSG_ERR.size()));
      unused(linux::oo_write(pipe_wr, err_text.data(), err_text.length()));
      pipe_wr.reset(-1);
      exit(EXIT_FAILURE);
    }

    insist(!ret.is_err(), "daemon_pid extraction requires the success branch");
    let daemon_pid = ret.get_value();
    insist(daemon_pid > 0, "start_daemon must return a valid child PID");

    // SECURITY: Namespace setup is complete; monitoring process only waits.
    // Switch back to the invoking user so `ps` shows the monitor under
    // the human's uid (not oorunner), and clear caps so the reaper holds
    // no elevated privileges.
    unused(privilege_drop::switch_to_user(INVOKING_UID, INVOKING_GID));
    unused(caps::drop_for_exec());

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
  m_child_pid =
      std::stoi(std::string{msg.substr(constants::DAEMON_MSG_OK.size())});

  trace(verbosity::info, "Daemon spawned successfully, PID: {}", child_pid);

  return child_pid;
}

fn satan::enter_namespace(pid_t daemon_pid, pid_t inner_pid) -> error_or<ok>
{
  trace_variables(verbosity::debug, daemon_pid, inner_pid);
  let net_ns_path = "/proc/" + std::to_string(daemon_pid) + "/ns/net";
  linux::oo_fd net_fd{unwrap(linux::oo_open(net_ns_path.c_str(), O_RDONLY))};

  // inner_pid unshared CLONE_NEWNS and applied bind mounts; daemon_pid did not.
  let mnt_pid = inner_pid != 0 ? inner_pid : daemon_pid;
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

fn satan::save() const -> error_or<ok>
{
  trace_self(verbosity::debug);
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

fn satan::sweep_orphans() -> error_or<ok>
{
  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec) || ec) {
    return ok{};
  }

  for (let &entry :
       std::filesystem::directory_iterator(constants::OO_RUN_DIR, ec))
  {
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
    satan probe{probe_ns};

    bool orphan = false;
    if (probe.load().is_err()) {
      orphan = true;
    } else if (!pid_tracker::is_alive_with_start_time(
                   probe.get_daemon_pid(), probe.get_daemon_start_time()))
    {
      orphan = true;
    }

    if (!orphan) {
      continue;
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
    if (!stat_ec && target_status.type() == std::filesystem::file_type::symlink)
    {
      return make_error("Refusing to clean orphan '" + name + "': target " +
                        target.string() + " is a symlink");
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

fn satan::execute(const std::vector<std::string> &argv) -> error_or<ok>
{
  insist(!argv.empty(), "satan::execute requires at least one argv element");
  insist(!argv[0].empty(), "argv[0] must be the program path for execvp");
  trace_self(verbosity::debug);

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
  unwrap(privilege_drop::switch_to_user(INVOKING_UID, INVOKING_GID));

  // SECURITY: Drop all capabilities before exec. setns() (enter_namespace)
  // already ran in this process using its file capabilities. The exec'd
  // command runs inside the namespace and needs no elevated privileges.
  unwrap(caps::drop_for_exec());

  trace(verbosity::info, "Executing: {}", argv[0]);
  unwrap(linux::oo_exec(argv));

  unreachable();
}

} // namespace oo
