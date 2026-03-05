#include "signal_handler.hh"
#include "commands.hh"
#include "debug.hh"

#include <cstdlib>

namespace oo {

fn signal_handler::setup() -> void {
  struct sigaction sa{};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  unused(oo_linux_syscall(sigaction, SIGINT, &sa, nullptr));
  unused(oo_linux_syscall(sigaction, SIGTERM, &sa, nullptr));
  unused(oo_linux_syscall(sigaction, SIGHUP, &sa, nullptr));

  trace(verbosity::debug, "Signal handlers registered");
}

fn signal_handler::register_cleanup(std::function<void()> callback) -> void {
  s_cleanup_callback = callback;
}

fn signal_handler::set_cleanup_state(std::shared_ptr<cleanup_state> state)
    -> void {
  s_cleanup_state = state;
}

fn signal_handler::clear_cleanup() -> void {
  s_cleanup_callback = nullptr;
  s_cleanup_state = nullptr;
}

fn signal_handler::was_interrupted() -> bool {
  return s_shutdown_requested != 0;
}

fn signal_handler::do_cleanup() -> void { cleanup_on_signal(); }

void signal_handler::cleanup_on_signal() {
  if (s_cleanup_state && s_cleanup_state->ns) {
    trace(verbosity::info, "Cleaning up network interfaces...");
    cleanup_namespace(*s_cleanup_state->ns, s_cleanup_state->subnet_octet,
                      s_cleanup_state->veth_host);
  }

  if (s_cleanup_callback) {
    s_cleanup_callback();
  }
}

fn signal_handler::trigger_shutdown() -> void {
  if (s_shutdown_requested) {
    return;
  }
  s_shutdown_requested = 1;

  trace(verbosity::info, "Shutdown requested, cleaning up...");
  cleanup_on_signal();
  exit(0);
}

void signal_handler::handle_signal(int sig) {
  trace(verbosity::info, "Received signal `{}`, shutting down", sig);
  trigger_shutdown();
}

} // namespace oo
