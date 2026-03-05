#pragma once

#include "common.hh"

#include <csignal>
#include <functional>
#include <memory>
#include <string>

namespace oo {

// Forward declarations
class network_configurator;
class ip_pool;
struct subnet;
class linux_namespace;

struct cleanup_state {
  linux_namespace *ns;
  u8 subnet_octet;
  std::string veth_host;
};

class signal_handler {
public:
  static fn setup() -> void;
  static fn register_cleanup(std::function<void()> callback) -> void;
  static fn set_cleanup_state(std::shared_ptr<cleanup_state> state) -> void;
  static fn trigger_shutdown() -> void;
  static fn clear_cleanup() -> void;
  static fn was_interrupted() -> bool;
  static fn do_cleanup() -> void;

private:
  static void handle_signal(int sig);
  static void cleanup_on_signal();
  static inline std::function<void()> s_cleanup_callback{nullptr};
  static inline std::shared_ptr<cleanup_state> s_cleanup_state{nullptr};
  static inline volatile sig_atomic_t s_shutdown_requested{0};
};

class cleanup_guard {
public:
  cleanup_guard() = default;

  fn disarm() -> void { armed = false; }

  ~cleanup_guard() {
    if (armed) {
      signal_handler::do_cleanup();
    }
  }

private:
  bool armed{true};
};

} // namespace oo
