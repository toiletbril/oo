#pragma once

#include "common.hh"
#include "error.hh"

#include <cerrno>
#include <cstring>
#include <string>
#include <system_error>
#include <unistd.h>
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

// Helper functions for common syscalls
fn oo_kill(pid_t pid, int signal) -> error_or<ok>;
fn oo_sleep_ms(int milliseconds) -> error_or<ok>;
fn oo_open(const char *path, int flags) -> error_or<fd>;
fn oo_close(fd fd) -> error_or<ok>;

// Helper for converting error_code to error_or
fn check_error_code(std::error_code ec, std::string_view context)
    -> error_or<ok>;

// Helper for checking non-zero/non-nullptr returns
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
