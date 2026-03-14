#pragma once

#include "common.hh"
#include "error.hh"

#include <csignal>
#include <functional>
#include <vector>

namespace oo {

class cleanup_guard {
public:
  cleanup_guard();
  ~cleanup_guard();

  fn add_cleanup(std::function<void()> cleanup_fn) -> void;
  fn disarm() -> void;

private:
  std::vector<std::function<void()>> m_cleanups;
  bool m_armed{true};

  fn run_cleanups() -> void;

  static void handle_signal(int sig);
  static inline cleanup_guard *s_active_guard{nullptr};
  static inline volatile sig_atomic_t s_shutdown_requested{0};
};

} // namespace oo
