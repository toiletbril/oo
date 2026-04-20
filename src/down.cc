#include "down.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "satan.hh"

#include <csignal>
#include <filesystem>

namespace oo {

static fn cleanup_namespace(linux_namespace &ns, network_configurator &netconf)
    -> void
{
  unused(netconf.cleanup());

  ip_pool pool{ns};
  const subnet s{netconf.get_subnet_octet()};
  unused(pool.free(s));

  let ns_path_result = ns.get_path();
  if (!ns_path_result.is_err()) {
    std::error_code ec;
    std::filesystem::remove_all(ns_path_result.get_value(), ec);
    if (ec) {
      trace(verbosity::error, "Failed to remove namespace directory: {}",
            ec.message());
    } else {
      trace(verbosity::debug, "Removed namespace directory: {}",
            ns_path_result.get_value().string());
    }
  }
}

fn down(cli::cli &&cli) -> error_or<ok>
{
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
    unsigned long parsed = strtoul(timeout_str.c_str(), &end, 10);
    if (end == timeout_str.c_str() || *end != '\0') {
      return make_error("Invalid --timeout value: " + timeout_str);
    }
    timeout_s = static_cast<usize>(parsed);
  }

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  linux_namespace ns{ns_name};

  satan s{ns};
  if (let r = s.load(); r.is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  network_configurator netconf{ns, subnet{0}};
  if (let r = netconf.load(); r.is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  // Graceful shutdown with timeout.
  if (s.get_daemon_pid() > 0) {
    if (pid_tracker::is_alive(s.get_daemon_pid())) {
      trace(verbosity::info, "Sending SIGTERM to daemon PID {}",
            s.get_daemon_pid());
      unwrap(linux::oo_kill(s.get_daemon_pid(), SIGTERM));

      let iterations = timeout_s * 1000 / constants::GRACEFUL_SHUTDOWN_SLEEP_MS;
      for (usize i = 0; i < iterations; ++i) {
        if (!pid_tracker::is_alive(s.get_daemon_pid())) {
          trace(verbosity::debug, "Daemon terminated gracefully");
          break;
        }
        unwrap(linux::oo_sleep_ms(constants::GRACEFUL_SHUTDOWN_SLEEP_MS));
      }

      if (pid_tracker::is_alive(s.get_daemon_pid())) {
        trace(verbosity::error, "Daemon did not terminate, sending SIGKILL");
        unwrap(linux::oo_kill(s.get_daemon_pid(), SIGKILL));
        unwrap(linux::oo_sleep_ms(constants::FORCEFUL_SHUTDOWN_SLEEP_MS));
      }
    } else {
      trace(verbosity::error, "Daemon PID {} not running (stale)",
            s.get_daemon_pid());
    }
  }

  cleanup_namespace(ns, netconf);

  trace(verbosity::info, "Namespace `{}` is down", ns_name);

  return ok{};
}

} // namespace oo
