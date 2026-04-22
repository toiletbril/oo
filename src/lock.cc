#include "lock.hh"

#include "debug.hh"
#include "linux_util.hh"

#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace oo {

file_lock::file_lock(std::filesystem::path path) : m_path(std::move(path)) {}

file_lock::file_lock(file_lock &&other) noexcept
    : m_path(std::move(other.m_path)), m_fd(other.m_fd) {
  other.m_fd = -1;
}

file_lock::~file_lock() {
  if (m_fd >= 0) {
    if (let r = release(); r.is_err()) {
      trace(verbosity::error, "Failed to release file lock on {}: {}",
            m_path.string(), r.get_error().get_reason());
    }
  }
}

fn file_lock::acquire() -> error_or<ok> {
  insist(!m_path.empty(), "file_lock constructed with empty path");
  if (m_fd >= 0) {
    return make_error("Lock already held on " + m_path.string());
  }

  m_fd = ::open(m_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (m_fd < 0) {
    return make_error("Could not open lock file: " + m_path.string() + ": " +
                      linux::get_errno_string());
  }
  insist(m_fd >= 0, "open returned a valid fd then went negative");

  struct flock fl{};
  fl.l_type = F_WRLCK;
  if (::fcntl(m_fd, F_SETLKW, &fl) != 0) {
    unwrap(linux::oo_close(m_fd));
    m_fd = -1;
    return make_error("Could not acquire lock on " + m_path.string() + ": " +
                      linux::get_errno_string());
  }

  let pid = std::to_string(getpid());
  insist(!pid.empty(), "getpid produced empty string");
  unwrap(oo_linux_syscall(write, m_fd, pid.data(), pid.length()));

  trace(verbosity::debug, "Acquired lock on {}", m_path.string());
  return ok{};
}

fn file_lock::release() -> error_or<ok> {
  if (m_fd < 0) {
    return make_error("No lock held on " + m_path.string());
  }
  insist(!m_path.empty(), "file_lock has an fd but no path");

  ::close(m_fd);
  m_fd = -1;

  trace(verbosity::debug, "Released lock on {}", m_path.string());
  return ok{};
}

} // namespace oo
