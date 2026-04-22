#pragma once

#include "common.hh"
#include "error.hh"

#include <filesystem>

namespace oo {

// RAII wrapper around an fcntl F_WRLCK on a dedicated lock file.
// Acquire is blocking; release happens on destruction. Move-only.
class file_lock {
public:
  explicit file_lock(std::filesystem::path path);
  ~file_lock();

  file_lock(file_lock &&other) noexcept;
  file_lock(const file_lock &) = delete;
  file_lock &operator=(const file_lock &) = delete;
  file_lock &operator=(file_lock &&) = delete;

  [[nodiscard]] fn acquire() -> error_or<ok>;
  fn release() -> error_or<ok>;
  [[nodiscard]] fn is_held() const -> bool { return m_fd >= 0; }

private:
  std::filesystem::path m_path;
  int m_fd{-1};
};

} // namespace oo
