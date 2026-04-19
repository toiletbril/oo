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
    -> void {
  unused(netconf.cleanup());

  ip_pool pool;
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

fn down(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo down [-options] <namespace>", "todo");

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

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  linux_namespace ns{ns_name};

  satan s{ns};
  unwrap(s.load());

  network_configurator netconf{ns, subnet{0}};
  unwrap(netconf.load());

  // Graceful shutdown with timeout.
  if (s.get_daemon_pid() > 0) {
    if (pid_tracker::is_alive(s.get_daemon_pid())) {
      trace(verbosity::info, "Sending SIGTERM to daemon PID {}",
            s.get_daemon_pid());
      unwrap(linux::oo_kill(s.get_daemon_pid(), SIGTERM));

      for (usize i = 0; i < constants::GRACEFUL_SHUTDOWN_ITERATIONS; ++i) {
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
