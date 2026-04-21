#include "linux_util.hh"

#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <sys/capability.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace oo {

namespace linux {

fn get_errno_string() -> std::string { return std::strerror(errno); }

fn get_error_string(int errnum) -> std::string { return std::strerror(errnum); }

fn raise_capability(int cap) -> error_or<ok>
{
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
    -> std::vector<const char *>
{
  std::vector<const char *> os_args;
  os_args.reserve(args.size() + 1);

  for (const std::string &arg : args)
    os_args.push_back(arg.c_str());

  os_args.push_back(nullptr);

  return os_args;
}

fn oo_exec(const std::vector<std::string> &args) -> error_or<ok>
{
  insist(!args.empty() && !args[0].empty(),
         "oo_exec requires argv[0] as the program path");
  let os_args = make_linux_args(args);
  let result = oo_linux_syscall(execvp, os_args[0],
                                const_cast<char *const *>(os_args.data()));
  if (result.is_err()) {
    return result.get_error();
  }
  unreachable();
}

fn oo_kill(pid_t pid, int signal) -> error_or<ok>
{
  trace_variables(verbosity::debug, pid, signal);
  unwrap(oo_linux_syscall(kill, pid, signal));
  return ok{};
}

fn oo_sleep_ms(int milliseconds) -> error_or<ok>
{
  trace_variables(verbosity::debug, milliseconds);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
  return ok{};
}

fn oo_open(const char *path, int flags) -> error_or<fd>
{
  trace_variables(verbosity::debug, path, flags);
  insist(path != nullptr, "oo_open requires a non-null path. Fuck you");
  return oo_linux_syscall(open, path, flags);
}

fn oo_close(fd fd) -> error_or<ok>
{
  trace_variables(verbosity::debug, fd);
  unwrap(oo_linux_syscall(close, fd));
  return ok{};
}

fn oo_fork() -> error_or<pid_t>
{
  let result = oo_linux_syscall(fork);
  if (result.is_err()) return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_pipe() -> error_or<std::pair<oo_fd, oo_fd>>
{
  int pipes[2];
  unwrap(oo_linux_syscall(pipe, pipes));
  return std::pair<oo_fd, oo_fd>{oo_fd{pipes[0]}, oo_fd{pipes[1]}};
}

fn oo_dup2(int src, int dst) -> error_or<ok>
{
  trace_variables(verbosity::debug, src, dst);
  unwrap(oo_linux_syscall(dup2, src, dst));
  return ok{};
}

fn oo_read(int fd, void *buf, usize count) -> error_or<ssize_t>
{
  let result = oo_linux_syscall(read, fd, buf, count);
  if (result.is_err()) return result.get_error();
  return static_cast<ssize_t>(result.get_value());
}

fn oo_write(int fd, const void *buf, usize count) -> error_or<ssize_t>
{
  let result = oo_linux_syscall(write, fd, buf, count);
  if (result.is_err()) return result.get_error();
  return static_cast<ssize_t>(result.get_value());
}

fn oo_waitpid(pid_t pid, int *status, int options) -> error_or<pid_t>
{
  trace_variables(verbosity::debug, pid, options);
  let result = oo_linux_syscall(waitpid, pid, status, options);
  if (result.is_err()) return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_setuid(uid_t uid) -> error_or<ok>
{
  trace_variables(verbosity::debug, uid);
  unwrap(oo_linux_syscall(setuid, uid));
  return ok{};
}

fn oo_setsid() -> error_or<pid_t>
{
  let result = oo_linux_syscall(setsid);
  if (result.is_err()) return result.get_error();
  return static_cast<pid_t>(result.get_value());
}

fn oo_unshare(int flags) -> error_or<ok>
{
  trace_variables(verbosity::debug, flags);
  unwrap(oo_linux_syscall(::unshare, flags));
  return ok{};
}

fn oo_setns(int fd, int nstype) -> error_or<ok>
{
  trace_variables(verbosity::debug, fd, nstype);
  unwrap(oo_linux_syscall(setns, fd, nstype));
  return ok{};
}

fn oo_lseek(int fd, off_t offset, int whence) -> error_or<off_t>
{
  trace_variables(verbosity::debug, fd, offset, whence);
  off_t ret = ::lseek(fd, offset, whence);
  if (ret == (off_t) -1) {
    return make_error("`lseek()` failed: " + get_errno_string());
  }
  return ret;
}

fn oo_chdir(const char *path) -> error_or<ok>
{
  insist(path != nullptr, "oo_chdir requires a non-null path");
  trace_variables(verbosity::debug, path);
  unwrap(oo_linux_syscall(chdir, path));
  return ok{};
}

fn check_error_code(std::error_code ec, std::string_view context)
    -> error_or<ok>
{
  if (ec) {
    return make_error(std::string{context} + ": " + ec.message());
  }
  return ok{};
}

} // namespace linux

} // namespace oo
