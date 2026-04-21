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

  // SECURITY: intentionally no SA_RESTART. Blocking syscalls interrupted
  // by a shutdown signal must return EINTR so error_or propagation unwinds
  // the stack back to this object's RAII destructor. Cleanups then run on
  // a normal call stack, not from inside the signal handler. The handler
  // itself is now async-signal-safe: it only sets a sig_atomic_t flag and,
  // on a second signal, calls _exit to break a wedged main loop.
  sa.sa_flags = 0;

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
  // SECURITY: async-signal-safe only. The handler does NOT dispatch the
  // registered std::function cleanups -- those may allocate, lock a
  // mutex, or touch glibc internals, none of which are safe to call from
  // a handler that may have interrupted malloc. Instead:
  //   1. Set a sig_atomic_t flag. Blocking syscalls in the main flow
  //      return EINTR (SA_RESTART is off), so error_or propagation
  //      unwinds the stack, and the destructor of this object runs the
  //      cleanups on a normal call stack.
  //   2. On a second signal, _exit immediately. A wedged main loop, or
  //      an operator who wants the process dead NOW, can override the
  //      graceful path with a second Ctrl-C.
  //
  // _exit is on the POSIX list of async-signal-safe functions. exit() is
  // not; using it here would invoke C++ destructors of unrelated globals
  // from signal context.
  if (s_shutdown_requested) {
    _exit(128 + sig);
  }
  s_shutdown_requested = 1;
}

} // namespace oo
