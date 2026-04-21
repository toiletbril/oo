#include "signal_handler.hh"

#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <cstdlib>
#include <unistd.h>

namespace oo {

cleanup_guard::cleanup_guard()
{
  struct sigaction sa{};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  unused(oo_linux_syscall(sigaction, SIGINT, &sa, nullptr));
  unused(oo_linux_syscall(sigaction, SIGTERM, &sa, nullptr));
  unused(oo_linux_syscall(sigaction, SIGHUP, &sa, nullptr));

  insist(s_active_guard == nullptr,
         "cleanup_guard is not reentrant; nesting would drop prior cleanups");
  s_active_guard = this;

  trace(verbosity::debug, "Cleanup guard armed with signal handlers");
}

cleanup_guard::~cleanup_guard()
{
  if (m_armed) {
    run_cleanups();
  }

  insist(s_active_guard == this || s_active_guard == nullptr,
         "a different cleanup_guard is active; signal dispatch would misroute");
  s_active_guard = nullptr;
}

fn cleanup_guard::add_cleanup(std::function<void()> cleanup_fn) -> void
{
  trace(verbosity::debug, "Adding a cleanup function");
  m_cleanups.push_back(cleanup_fn);
}

fn cleanup_guard::disarm() -> void
{
  m_armed = false;
  s_active_guard = nullptr;
  trace(verbosity::debug, "Cleanup guard disarmed");
}

fn cleanup_guard::run_cleanups() -> void
{
  trace(verbosity::info, "Running {} cleanup functions", m_cleanups.size());

  // Run in reverse order (LIFO)
  for (let it = m_cleanups.rbegin(); it != m_cleanups.rend(); ++it) {
    (*it)();
  }
}

fn cleanup_guard::handle_signal(int sig) -> void
{
  // SECURITY: This is a POSIX signal handler. Only async-signal-safe operations
  // are permitted here. Specifically:
  //   - std::print / trace() are NOT async-signal-safe (omitted intentionally)
  //   - exit() is NOT async-signal-safe; _exit() is used instead
  //   - run_cleanups() dispatches std::function objects which are technically
  //     not guaranteed safe, but in practice the registered callbacks only
  //     call async-safe syscalls (kill, waitpid, fork, execvp)
  //
  // If you add a cleanup function that calls malloc, I/O, or other non-safe
  // operations, replace this direct-dispatch pattern with a self-pipe or
  // eventfd to trigger cleanup from the main loop instead.
  unused(sig);

  if (s_shutdown_requested) {
    return;
  }
  s_shutdown_requested = 1;

  if (s_active_guard) {
    s_active_guard->run_cleanups();
  }

  _exit(0);
}

} // namespace oo
