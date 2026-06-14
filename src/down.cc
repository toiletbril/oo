#include "down.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"
#include "satan.hh"

#include <csignal>

namespace oo {

fn down(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo down [-options] <namespace>",
                   "Stop the daemon and tear down the namespace.");

  let &flag_timeout = cli.add_flag<cli::flag_string>(
      '\0', "timeout", "Seconds to wait for graceful shutdown. Default: 10.");
  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  if (args.empty()) {
    return make_error(
        "Missing namespace name. Try '--help' for more information.");
  }

  usize timeout_s = 10;
  if (flag_timeout.is_set()) {
    const std::string timeout_str{flag_timeout.get_value()};
    char *end = nullptr;
    u64 parsed = strtoul(timeout_str.c_str(), &end, 10);
    if (end == timeout_str.c_str() || *end != '\0') {
      return make_error("The --timeout value '" + timeout_str +
                        "' is not a valid number");
    }
    if (parsed > 3600) {
      return make_error("--timeout must be <= 3600");
    }
    timeout_s = static_cast<usize>(parsed);
  }

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  linux_namespace ns{ns_name};

  passwd pw;
  satan s{ns, pw};
  if (let r = s.load(); r.is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  if (!s.is_accessible_by(pw.get_invoking_uid())) {
    return make_error("Namespace '" + ns_name + "' is owned by another user");
  }

  network_configurator netconf{ns, subnet{0}};
  if (let r = netconf.load(); r.is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  // Stopping the daemon means stopping the whole process group it leads. The
  // monitor created a new session (setsid) before forking the daemon, so the
  // group id equals the monitor pid recorded as daemon_pid. Signalling the
  // group reaches the actual daemon and anything it spawned, not just the
  // monitor that only reaps it. The start-time check still guards against pid
  // reuse before we touch the group. Kills are best effort so a race or
  // transient errno never aborts teardown and leaks the veth, NAT rules,
  // namespace directory, and subnet.
  if (s.get_daemon_pid() > 0 &&
      pid_tracker::is_alive_with_start_time(s.get_daemon_pid(),
                                            s.get_daemon_start_time())) {
    const pid_t group = s.get_daemon_pid();
    trace(verbosity::info, "Sending SIGTERM to daemon group {}", group);
    unused(linux::oo_kill(-group, SIGTERM));

    let iterations = timeout_s * 1000 / constants::GRACEFUL_SHUTDOWN_SLEEP_MS;
    for (usize i = 0; i < iterations; ++i) {
      if (::kill(-group, 0) != 0) {
        trace(verbosity::debug, "Daemon group terminated gracefully");
        break;
      }
      unwrap(linux::oo_sleep_ms(constants::GRACEFUL_SHUTDOWN_SLEEP_MS));
    }

    if (::kill(-group, 0) == 0) {
      trace(verbosity::error,
            "Daemon group did not terminate, sending SIGKILL");
      unused(linux::oo_kill(-group, SIGKILL));
      unwrap(linux::oo_sleep_ms(constants::FORCEFUL_SHUTDOWN_SLEEP_MS));
    }
  } else if (s.get_daemon_pid() > 0) {
    trace(verbosity::error, "Daemon PID {} not running (stale)",
          s.get_daemon_pid());
  }

  // The proxy is its own session leader (it calls setsid in spawn_proxy), so it
  // forms a separate group. Signal that group too so per-connection handler
  // children stop with it. This runs under the invoking user, before the switch
  // to oorunner below.
  if (s.get_proxy_pid() > 0 &&
      pid_tracker::is_alive_with_start_time(s.get_proxy_pid(),
                                            s.get_proxy_start_time())) {
    const pid_t group = s.get_proxy_pid();
    trace(verbosity::info, "Sending SIGTERM to proxy group {}", group);
    unused(linux::oo_kill(-group, SIGTERM));

    let iterations = timeout_s * 1000 / constants::GRACEFUL_SHUTDOWN_SLEEP_MS;
    for (usize i = 0; i < iterations; ++i) {
      if (::kill(-group, 0) != 0) {
        break;
      }
      unwrap(linux::oo_sleep_ms(constants::GRACEFUL_SHUTDOWN_SLEEP_MS));
    }

    if (::kill(-group, 0) == 0) {
      trace(verbosity::error, "Proxy group did not terminate, sending SIGKILL");
      unused(linux::oo_kill(-group, SIGKILL));
    }
  }

  // SECURITY: the daemon was owned by the invoking user; the kill above had
  // to run as that same uid, so `oo.cc` deferred the oorunner switch for
  // `down`. Perform the switch now -- the remaining work (removing the
  // namespace directory, writing ip-pool.ini) must happen under oorunner
  // because that is the account that owns /var/run/oo.
  unwrap(pw.su_oorunner());

  unused(ns.reset(netconf));
  ip_pool pool{ns};
  unused(pool.free(subnet{netconf.get_subnet_octet()}));

  unused(s.sweep_orphans());

  trace(verbosity::info, "Namespace `{}` is down", ns_name);

  return ok{};
}

} // namespace oo
