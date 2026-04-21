#pragma once

#include "common.hh"
#include "error.hh"

#include <cerrno>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace oo {

namespace linux {

using fd = int;

fn get_errno_string() -> std::string;
fn get_error_string(int errnum) -> std::string;
fn raise_capability(int cap) -> error_or<ok>;

template <typename F, typename... Args>
fn oo_linux_syscall_impl(const char *text, F syscall_fn, Args... args)
    -> error_or<int>
{
  int ret = syscall_fn(args...);
  if (ret < 0) {
    return make_error("`" + std::string{text} +
                      "` failed: " + get_errno_string());
  }
  return ret;
}

#define oo_linux_syscall(fn, ...)                                              \
  (oo::linux::oo_linux_syscall_impl(#fn "(" #__VA_ARGS__ ")", fn,              \
                                    ##__VA_ARGS__))

fn make_linux_args(const std::vector<std::string> &args)
    -> std::vector<const char *>;

fn oo_exec(const std::vector<std::string> &args) -> error_or<ok>;

// Helper functions for common syscalls.
fn oo_kill(pid_t pid, int signal) -> error_or<ok>;
fn oo_sleep_ms(int milliseconds) -> error_or<ok>;
fn oo_open(const char *path, int flags) -> error_or<fd>;
fn oo_close(fd fd) -> error_or<ok>;
fn oo_fork() -> error_or<pid_t>;
fn oo_dup2(int src, int dst) -> error_or<ok>;
fn oo_read(int fd, void *buf, usize count) -> error_or<ssize_t>;
fn oo_write(int fd, const void *buf, usize count) -> error_or<ssize_t>;
fn oo_waitpid(pid_t pid, int *status, int options) -> error_or<pid_t>;
fn oo_setuid(uid_t uid) -> error_or<ok>;
fn oo_setsid() -> error_or<pid_t>;
fn oo_unshare(int flags) -> error_or<ok>;
fn oo_setns(int fd, int nstype) -> error_or<ok>;
fn oo_lseek(int fd, off_t offset, int whence) -> error_or<off_t>;
fn oo_chdir(const char *path) -> error_or<ok>;

// RAII wrapper around a file descriptor. Closes on destruction, move-only.
// Use to make fd lifetime a type property rather than a defer convention.
class oo_fd
{
public:
  oo_fd() = default;
  explicit oo_fd(int fd) : m_fd(fd) {}

  oo_fd(const oo_fd &) = delete;
  oo_fd &operator=(const oo_fd &) = delete;

  oo_fd(oo_fd &&other) noexcept : m_fd(other.m_fd) { other.m_fd = -1; }

  oo_fd &operator=(oo_fd &&other) noexcept
  {
    if (this != &other) {
      reset(other.m_fd);
      other.m_fd = -1;
    }
    return *this;
  }

  ~oo_fd() { reset(-1); }

  fn get() const -> int { return m_fd; }
  operator int() const { return m_fd; }

  fn is_valid() const -> bool { return m_fd >= 0; }

  fn release() -> int
  {
    int out = m_fd;
    m_fd = -1;
    return out;
  }

  fn reset(int new_fd) -> void
  {
    if (m_fd >= 0) unused(oo_close(m_fd));
    m_fd = new_fd;
  }

private:
  int m_fd{-1};
};

fn oo_pipe() -> error_or<std::pair<oo_fd, oo_fd>>;

// Helper for converting error_code to error_or.
fn check_error_code(std::error_code ec, std::string_view context)
    -> error_or<ok>;

// Helper for checking non-zero/non-nullptr returns.
template <typename T>
fn check_non_zero(T value, std::string_view context) -> error_or<T>
{
  if (value == T{}) {
    return make_error(std::string{context} + ": " + get_errno_string());
  }
  return value;
}

#define oo_error_code(ec, msg) (oo::linux::check_error_code(ec, msg))
#define oo_non_zero(val, msg)  (oo::linux::check_non_zero(val, msg))

} // namespace linux

} // namespace oo
