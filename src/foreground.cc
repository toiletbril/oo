#include "foreground.hh"

#include "cli.hh"
#include "debug.hh"
#include "ip_pool.hh"
#include "linux_util.hh"
#include "pid_tracker.hh"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <sys/wait.h>
#include <unistd.h>

namespace oo {

namespace {

constexpr usize TAIL_POLL_SLEEP_MS = 50;
constexpr usize TAIL_READ_BUFFER = 8192;
constexpr usize FORWARDER_PROXY_GRACE_MS = 5000;
constexpr usize FORWARDER_PROXY_TICK_MS = 50;

volatile sig_atomic_t g_forwarder_signal_count = 0;
volatile sig_atomic_t g_forwarder_monitor_pid = 0;
volatile sig_atomic_t g_forwarder_proxy_pid = 0;

// Returns a string literal, so it is safe to read from a signal handler.
fn signal_name(int sig) -> const char * {
  switch (sig) {
  case SIGHUP:
    return "SIGHUP";
  case SIGINT:
    return "SIGINT";
  case SIGQUIT:
    return "SIGQUIT";
  case SIGILL:
    return "SIGILL";
  case SIGABRT:
    return "SIGABRT";
  case SIGBUS:
    return "SIGBUS";
  case SIGFPE:
    return "SIGFPE";
  case SIGKILL:
    return "SIGKILL";
  case SIGSEGV:
    return "SIGSEGV";
  case SIGPIPE:
    return "SIGPIPE";
  case SIGTERM:
    return "SIGTERM";
  default:
    return "an unknown signal";
  }
}

// The forwarder relays these on a terminal signal and escalates to SIGKILL.
// A daemon brought down by one of them was stopped at the user's request,
// not crashed, so foreground supervise reports a clean stop for it.
fn is_relayed_signal(int sig) -> bool {
  return sig == SIGINT || sig == SIGTERM || sig == SIGHUP || sig == SIGKILL;
}

// Async-signal-safe notice that the forwarder is relaying a signal. The line
// is built in a stack buffer and emitted with a single write, with no
// allocation, locks, or stdio, so it is safe to call from a signal handler.
fn write_relay_notice(int sig) -> void {
  char buf[64];
  usize n = 0;
  const char prefix[] = "oo: relaying ";
  for (usize i = 0; prefix[i] != '\0'; ++i) {
    buf[n++] = prefix[i];
  }

  const char *name = signal_name(sig);
  for (usize i = 0; name[i] != '\0'; ++i) {
    buf[n++] = name[i];
  }

  const char suffix[] = " to the daemon...\n";
  for (usize i = 0; suffix[i] != '\0'; ++i) {
    buf[n++] = suffix[i];
  }

  unused(::write(STDERR_FILENO, buf, n));
}

fn forwarder_handle_signal(int sig) -> void {
  g_forwarder_signal_count += 1;
  // Second-and-later signals escalate to SIGKILL so a daemon that ignores
  // the original signal still dies. The forwarder itself stays alive until
  // the parent wakes it via the wake pipe; this gives the daemon time to
  // exit before namespace teardown runs and avoids a wedge where the
  // parent loop has no remaining escape path.
  let to_send = g_forwarder_signal_count > 1 ? SIGKILL : sig;
  write_relay_notice(to_send);
  let monitor = g_forwarder_monitor_pid;
  if (monitor > 0) {
    unused(::kill(-monitor, to_send));
  }
  let proxy = g_forwarder_proxy_pid;
  if (proxy > 0) {
    unused(::kill(-proxy, to_send));
  }
}

fn drain_log_fd(int log_fd, int dst_fd) -> void {
  char buf[TAIL_READ_BUFFER];
  for (;;) {
    let n = ::read(log_fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return;
    }
    if (n == 0) {
      return;
    }
    usize off = 0;
    while (off < static_cast<usize>(n)) {
      let w = ::write(dst_fd, buf + off, static_cast<usize>(n) - off);
      if (w < 0) {
        if (errno == EINTR) {
          continue;
        }
        return;
      }
      if (w == 0) {
        return;
      }
      off += static_cast<usize>(w);
    }
  }
}

fn open_log(const std::filesystem::path &p, bool seek_to_end)
    -> error_or<linux::oo_fd> {
  // The daemon may not have written anything yet, so a missing log is fine.
  // O_CREAT makes the first read a clean empty stream until the daemon
  // flushes its first bytes. The 0644 mode matches what the daemon side
  // uses, so ownership stays consistent.
  int raw = ::open(p.c_str(), O_RDONLY | O_CREAT | O_CLOEXEC, 0644);
  if (raw < 0) {
    return make_error("Cannot open log file " + p.string() + ": " +
                      linux::get_errno_string());
  }
  linux::oo_fd fd{raw};
  if (seek_to_end && ::lseek(fd, 0, SEEK_END) == static_cast<off_t>(-1)) {
    return make_error("Cannot seek to end of log file " + p.string() + ": " +
                      linux::get_errno_string());
  }
  return fd;
}

fn install_handler(int sig, void (*handler)(int), struct sigaction *old)
    -> void {
  struct sigaction sa{};
  sa.sa_handler = handler;
  // Block the three terminal signals while the handler runs. The forwarder
  // handler does a non-atomic read-modify-write on g_forwarder_signal_count,
  // so a sibling signal interrupting it mid-update would lose the increment
  // and defer the SIGKILL escalation. The mask is harmless for the SIG_IGN
  // and SIG_DFL dispositions installed through this helper.
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTERM);
  sigaddset(&sa.sa_mask, SIGHUP);
  unused(::sigaction(sig, &sa, old));
}

fn restore_handler(int sig, const struct sigaction *saved) -> void {
  unused(::sigaction(sig, saved, nullptr));
}

fn stop_proxy_group_best_effort(pid_t group) -> void {
  if (group <= 0) {
    return;
  }
  unused(::kill(-group, SIGTERM));
  let iterations = FORWARDER_PROXY_GRACE_MS / FORWARDER_PROXY_TICK_MS;
  for (usize i = 0; i < iterations; ++i) {
    if (::kill(-group, 0) != 0) {
      return;
    }
    unused(linux::oo_sleep_ms(FORWARDER_PROXY_TICK_MS));
  }
  unused(::kill(-group, SIGKILL));
}

fn run_teardown(linux_namespace &ns, network_configurator &netconf, subnet sn)
    -> void {
  // Same call sequence `oo down` runs after the daemon group has been
  // stopped. Reset tears the namespace dir down and runs the netfilter
  // cleanup, then a freshly constructed ip_pool acquires the lock briefly
  // to free the subnet. Building the pool here rather than holding the
  // caller's keeps the lock out of the foreground wait, which otherwise
  // would serialise every concurrent up, down, and touch on every namespace.
  unused(ns.reset(netconf));
  ip_pool pool{ns};
  unused(pool.free(sn));
}

} // namespace

fn attach_and_supervise(pid_t monitor_pid, u64 monitor_start_time,
                        pid_t proxy_pid, u64 proxy_start_time,
                        linux_namespace &ns, network_configurator &netconf,
                        subnet sn, passwd &pw, bool should_tail_from_end)
    -> error_or<ok> {
  insist(monitor_pid > 0, "attach_and_supervise requires a valid monitor pid");

  // Drop a stale proxy pid before it reaches the forwarder. The caller has
  // checked the daemon, but the proxy may have died while the daemon stayed
  // up, which the attach path does not screen. Without this the forwarder
  // could signal a process group that reused the dead proxy's pid.
  if (proxy_pid > 0 &&
      !pid_tracker::is_alive_with_start_time(proxy_pid, proxy_start_time)) {
    proxy_pid = 0;
  }

  // The caller has already disarmed its cleanup guard and committed the
  // namespace state by the time it calls this, so a setup failure here
  // cannot roll the namespace back. The daemon stays running. Annotate the
  // error so the user knows to stop it by hand rather than assuming nothing
  // was created.
  let live_error = [&](const error &e) -> oo::error {
    return make_error(e.get_owned_reason() + " The daemon is still running; " +
                      "use `oo down " + ns.get_name() + "` to stop it.");
  };

  let ns_path_r = ns.get_path();
  if (ns_path_r.is_err()) {
    return live_error(ns_path_r.get_error());
  }
  let ns_path = ns_path_r.get_value();

  let stdout_r = open_log(ns_path / "stdout", should_tail_from_end);
  if (stdout_r.is_err()) {
    return live_error(stdout_r.get_error());
  }
  let stdout_fd = stdout_r.take();

  let stderr_r = open_log(ns_path / "stderr", should_tail_from_end);
  if (stderr_r.is_err()) {
    return live_error(stderr_r.get_error());
  }
  let stderr_fd = stderr_r.take();

  // The forwarder reads one byte from this pipe and exits. The parent
  // writes a byte once it has observed the monitor's exit, so the forwarder
  // unblocks even when no signal ever arrived from the terminal.
  let pipe_r = linux::oo_pipe();
  if (pipe_r.is_err()) {
    return live_error(pipe_r.get_error());
  }
  let[wake_rd, wake_wr] = pipe_r.take();

  // Block the three terminal signals across the fork so neither the parent
  // nor the forwarder child can be killed by the default disposition in
  // the window between fork and the install_handler calls below. Each side
  // installs its own handler and then unblocks.
  sigset_t block_set;
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGHUP);
  sigset_t prev_set;
  unused(::sigprocmask(SIG_BLOCK, &block_set, &prev_set));

  // Signal forwarding needs a separate process because of a uid boundary,
  // not for plumbing convenience. The parent runs as oorunner so it keeps
  // the capabilities the network and pool teardown require after the daemon
  // exits. The monitor and the daemon run as the invoking user. POSIX
  // permits a signal only when the sender's uid matches the target or the
  // sender holds CAP_KILL, and the oo binary does not carry CAP_KILL, so an
  // oorunner parent gets EPERM trying to signal the daemon group. The
  // forwarder is a child that drops to the invoking user once with pw.su,
  // after which its kills on the daemon and proxy groups are permitted,
  // while the parent stays oorunner for the teardown.
  let fork_r = linux::oo_fork();
  if (fork_r.is_err()) {
    unused(::sigprocmask(SIG_SETMASK, &prev_set, nullptr));
    return live_error(fork_r.get_error());
  }
  let forwarder_pid = fork_r.get_value();
  if (forwarder_pid == 0) {
    wake_wr.reset(-1);

    if (let r = pw.su(); r.is_err()) {
      _exit(EXIT_FAILURE);
    }

    linux::set_process_name("oo: foreground signal forwarder to process " +
                            std::to_string(monitor_pid) + " [" + ns.get_name() +
                            "]");

    g_forwarder_monitor_pid = monitor_pid;
    g_forwarder_proxy_pid = proxy_pid;
    struct sigaction discard{};
    install_handler(SIGINT, forwarder_handle_signal, &discard);
    install_handler(SIGTERM, forwarder_handle_signal, &discard);
    install_handler(SIGHUP, forwarder_handle_signal, &discard);

    unused(::sigprocmask(SIG_SETMASK, &prev_set, nullptr));

    char buf;
    for (;;) {
      let n = ::read(wake_rd, &buf, 1);
      if (n == 1 || n == 0) {
        // Either the parent woke us (n == 1) or the pipe closed under us
        // because the parent died (n == 0). In both cases stop the proxy
        // group before exit. The daemon group is already torn down or
        // about to be torn down by the parent's run_teardown, so do not
        // touch it again here. Stopping the proxy from the parent is not
        // an option because the parent stays as oorunner.
        stop_proxy_group_best_effort(g_forwarder_proxy_pid);
        _exit(EXIT_SUCCESS);
      }
      if (errno != EINTR) {
        _exit(EXIT_FAILURE);
      }
    }
  }

  wake_rd.reset(-1);

  // Capture each previous disposition so the function leaves the process
  // with whatever the caller had installed, rather than forcing SIG_DFL.
  struct sigaction saved_int{};
  struct sigaction saved_term{};
  struct sigaction saved_hup{};
  install_handler(SIGINT, SIG_IGN, &saved_int);
  install_handler(SIGTERM, SIG_IGN, &saved_term);
  install_handler(SIGHUP, SIG_IGN, &saved_hup);

  unused(::sigprocmask(SIG_SETMASK, &prev_set, nullptr));

  trace(verbosity::info,
        "Attached to namespace '{}'. Daemon group {}. Ctrl-C to stop.",
        ns.get_name(), monitor_pid);

  // Poll on a sleep tick because the log files are regular files and `poll`
  // always reports them as readable. The tick also paces the monitor check
  // without burning a core.
  //
  // Two exit detections are needed. In up and touch relaunch the monitor is
  // a direct child of this process, so a non-blocking waitpid both observes
  // its exit and reaps the zombie. A /proc liveness check cannot stand in
  // here, because a reaped-pending zombie still has /proc/<pid>/stat and
  // would read as alive forever, wedging the loop. In attach the monitor
  // belongs to another process, waitpid returns ECHILD, and the start-time
  // liveness check is the correct probe.
  int monitor_status = 0;
  bool have_monitor_status = false;
  for (;;) {
    drain_log_fd(stdout_fd, STDOUT_FILENO);
    drain_log_fd(stderr_fd, STDERR_FILENO);

    let waited = ::waitpid(monitor_pid, &monitor_status, WNOHANG);
    if (waited == monitor_pid) {
      have_monitor_status = true;
      break;
    }
    if (waited < 0 && errno == ECHILD &&
        !pid_tracker::is_alive_with_start_time(monitor_pid,
                                               monitor_start_time)) {
      break;
    }

    unused(linux::oo_sleep_ms(TAIL_POLL_SLEEP_MS));
  }

  // Final drain so output written between the last tick and the daemon's
  // exit reaches the terminal before the prompt comes back.
  drain_log_fd(stdout_fd, STDOUT_FILENO);
  drain_log_fd(stderr_fd, STDERR_FILENO);

  // Announce cleanup before the work below. Stopping the proxy group waits
  // up to a few seconds for it to exit, and the teardown that follows is
  // also not instant, so without this line the prompt appears to hang.
  cli::show_message("Daemon is dead. Cleaning up the namespace `" +
                    ns.get_name() + "`...");

  // Wake the forwarder so it can exit cleanly. EPIPE means the forwarder is
  // already gone (it took the second-signal path or the read returned 0);
  // SIGPIPE is ignored process-wide so the failed write is harmless and
  // the waitpid below still reaps the queued exit status.
  char wake = 1;
  unused(::write(wake_wr, &wake, 1));
  wake_wr.reset(-1);

  int forwarder_status = 0;
  unused(::waitpid(forwarder_pid, &forwarder_status, 0));

  run_teardown(ns, netconf, sn);

  restore_handler(SIGINT, &saved_int);
  restore_handler(SIGTERM, &saved_term);
  restore_handler(SIGHUP, &saved_hup);

  const std::string torn_down = "Tore down namespace `" + ns.get_name() +
                                "` because daemon process " +
                                std::to_string(monitor_pid);

  // Attach mode supervises a daemon owned by another process, so it cannot
  // waitpid it and never has an exit status. Report the observed
  // disappearance plainly rather than implying a clean or signalled exit.
  if (!have_monitor_status) {
    cli::show_message(torn_down + " is gone.");
    return ok{};
  }
  if (WIFEXITED(monitor_status)) {
    let code = WEXITSTATUS(monitor_status);
    if (code == 0) {
      return ok{};
    }
    return make_error(torn_down + " exited with status " +
                      std::to_string(code) + ".");
  }
  if (WIFSIGNALED(monitor_status)) {
    let sig = WTERMSIG(monitor_status);
    // A daemon stopped by a signal the forwarder relays was brought down at
    // the user's request, so report it as a clean stop rather than an error.
    if (is_relayed_signal(sig)) {
      cli::show_message(torn_down + " terminated via " + signal_name(sig) +
                        ".");
      return ok{};
    }
    return make_error(torn_down + " terminated via " + signal_name(sig) + ".");
  }
  return ok{};
}

} // namespace oo
