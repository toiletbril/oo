#include "linux_util.hh"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace oo {

namespace linux {

fn get_errno_string() -> std::string { return std::strerror(errno); }

fn get_error_string(int errnum) -> std::string { return std::strerror(errnum); }

namespace {
char **g_argv_start = nullptr;
usize g_argv_len = 0;
} // namespace

fn init_process_name(int argc, char **argv) -> void {
  g_argv_start = nullptr;
  g_argv_len = 0;
  if (argc <= 0 || argv == nullptr || argv[0] == nullptr) {
    return;
  }
  // argv strings are laid out contiguously. The writable span runs from
  // argv[0] to the end of the last argv string. The environment that follows
  // is left untouched.
  char *last = argv[argc - 1];
  if (last == nullptr) {
    return;
  }
  g_argv_start = argv;
  g_argv_len = static_cast<usize>(last + std::strlen(last) + 1 - argv[0]);
}

fn set_process_name(std::string_view name) -> void {
  char comm[16];
  usize comm_len =
      name.size() < sizeof(comm) - 1 ? name.size() : sizeof(comm) - 1;
  std::memcpy(comm, name.data(), comm_len);
  comm[comm_len] = '\0';
  unused(::prctl(PR_SET_NAME, comm));

  if (g_argv_start != nullptr && g_argv_len > 1) {
    usize n = name.size() < g_argv_len - 1 ? name.size() : g_argv_len - 1;
    std::memcpy(g_argv_start[0], name.data(), n);
    std::memset(g_argv_start[0] + n, 0, g_argv_len - n);
  }
}

fn raise_capability(int cap) -> error_or<ok> {
  trace_variables(verbosity::debug, cap);
  insist(cap >= 0 && cap <= CAP_LAST_CAP,
         "capability id must be within kernel range");
  cap_t caps = cap_get_proc();
  if (caps == nullptr) {
    return make_error("Failed to get process capabilities: " +
                      get_errno_string());
  }

  cap_value_t cap_list[] = {static_cast<cap_value_t>(cap)};
  if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) != 0) {
    cap_free(caps);
    return make_error("Failed to set capability flag: " + get_errno_string());
  }

  if (cap_set_proc(caps) != 0) {
    cap_free(caps);
    return make_error("Failed to activate capability: " + get_errno_string());
  }

  cap_free(caps);

  return ok{};
}

fn make_linux_args(const std::vector<std::string> &args)
    -> std::vector<const char *> {
  std::vector<const char *> os_args;
  os_args.reserve(args.size() + 1);

  for (const std::string &arg : args)
    os_args.push_back(arg.c_str());

  os_args.push_back(nullptr);

  return os_args;
}

fn oo_exec(const std::vector<std::string> &args) -> error_or<ok> {
  if (args.empty() || args[0].empty()) {
    return make_error("Cannot execute: no command given");
  }

  let os_args = make_linux_args(args);

  // SECURITY: wipe every inherited environment variable before exec. The
  // parent env is attacker-controlled; LD_PRELOAD, LD_LIBRARY_PATH,
  // LD_AUDIT, LOCPATH, or IFS in a child process would let the invoker
  // inject code into the exec'd binary. A minimal allowlist is then set so
  // the binary can still locate its own shared objects under a vanilla
  // loader policy. This is the single choke point for every exec in oo;
  // every caller (daemon, user command, iptables/nft child) gets the same
  // sanitized baseline.
  if (::clearenv() != 0) {
    return make_error("`clearenv()` failed before exec");
  }

  unused(oo_linux_syscall(setenv, "PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1));
  unused(oo_linux_syscall(setenv, "LANG", "C", 1));
  unused(oo_linux_syscall(setenv, "LC_ALL", "C", 1));

  // oo ignores SIGPIPE process-wide (see main), and SIG_IGN survives execve.
  // Restore the default so the exec'd program gets normal SIGPIPE behavior
  // rather than silently inheriting oo's ignore disposition.
  unused(::signal(SIGPIPE, SIG_DFL));

  let ret = oo_linux_syscall(::execvp, os_args[0],
                             const_cast<char *const *>(os_args.data()));
  insist(ret.is_err());

  return make_error("Cannot execute '" + args[0] +
                    "': " + ret.get_error().get_owned_reason());
}

fn oo_kill(pid_t pid, int signal) -> error_or<ok> {
  trace_variables(verbosity::debug, pid, signal);
  unwrap(oo_linux_syscall(kill, pid, signal));
  return ok{};
}

fn oo_sleep_ms(int milliseconds) -> error_or<ok> {
  trace_variables(verbosity::debug, milliseconds);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
  return ok{};
}

fn oo_open(const char *path, int flags) -> error_or<fd> {
  trace_variables(verbosity::debug, path, flags);
  insist(path != nullptr, "oo_open requires a non-null path. Fuck you");
  return oo_linux_syscall(open, path, flags);
}

fn oo_close(fd fd) -> error_or<ok> {
  trace_variables(verbosity::debug, fd);
  unwrap(oo_linux_syscall(close, fd));
  return ok{};
}

fn oo_fork() -> error_or<pid_t> {
  let result = oo_linux_syscall(fork);
  if (result.is_err())
    return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_pipe() -> error_or<std::pair<oo_fd, oo_fd>> {
  // SECURITY: pipe2 with O_CLOEXEC ensures neither end leaks across an exec.
  // Without it a downstream execvp inherits the pipe FDs, widening the
  // runtime FD surface past what the caller expects.
  int pipes[2];
  unwrap(oo_linux_syscall(pipe2, pipes, O_CLOEXEC));
  return std::pair<oo_fd, oo_fd>{oo_fd{pipes[0]}, oo_fd{pipes[1]}};
}

fn oo_dup2(int src, int dst) -> error_or<ok> {
  trace_variables(verbosity::debug, src, dst);
  unwrap(oo_linux_syscall(dup2, src, dst));
  return ok{};
}

fn oo_read(int fd, void *buf, usize count) -> error_or<ssize_t> {
  let result = oo_linux_syscall(read, fd, buf, count);
  if (result.is_err())
    return result.get_error();
  return static_cast<ssize_t>(result.get_value());
}

fn oo_write(int fd, const void *buf, usize count) -> error_or<ssize_t> {
  let result = oo_linux_syscall(write, fd, buf, count);
  if (result.is_err())
    return result.get_error();
  return static_cast<ssize_t>(result.get_value());
}

fn oo_waitpid(pid_t pid, int *status, int options) -> error_or<pid_t> {
  trace_variables(verbosity::debug, pid, options);
  let result = oo_linux_syscall(waitpid, pid, status, options);
  if (result.is_err())
    return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_setuid(uid_t uid) -> error_or<ok> {
  trace_variables(verbosity::debug, uid);
  unwrap(oo_linux_syscall(setuid, uid));
  return ok{};
}

fn oo_setsid() -> error_or<pid_t> {
  let result = oo_linux_syscall(setsid);
  if (result.is_err())
    return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_unshare(int flags) -> error_or<ok> {
  trace_variables(verbosity::debug, flags);
  unwrap(oo_linux_syscall(::unshare, flags));
  return ok{};
}

fn oo_setns(int fd, int nstype) -> error_or<ok> {
  trace_variables(verbosity::debug, fd, nstype);
  unwrap(oo_linux_syscall(setns, fd, nstype));
  return ok{};
}

fn oo_lseek(int fd, off_t offset, int whence) -> error_or<off_t> {
  trace_variables(verbosity::debug, fd, offset, whence);
  off_t ret = ::lseek(fd, offset, whence);
  if (ret == (off_t)-1) {
    return make_error("`lseek()` failed: " + get_errno_string());
  }
  return ret;
}

fn oo_chdir(const char *path) -> error_or<ok> {
  insist(path != nullptr, "oo_chdir requires a non-null path");
  trace_variables(verbosity::debug, path);
  unwrap(oo_linux_syscall(chdir, path));
  return ok{};
}

fn check_error_code(std::error_code ec, std::string_view context)
    -> error_or<ok> {
  if (ec) {
    return make_error(std::string{context} + ": " + ec.message());
  }
  return ok{};
}

} // namespace linux

} // namespace oo
