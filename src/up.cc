#include "up.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "dominatrix.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "satan.hh"
#include "signal_handler.hh"

#include <csignal>

namespace oo {

fn up(cli::cli &&cli) -> error_or<ok>
{
  cli.add_use_case(
      "oo up [-options] <namespace> [--] <daemon> [daemon-args...]",
      "Start a daemon in a new network namespace.");

  let &flag_dns = cli.add_flag<cli::flag_many_strings>(
      '\0', "dns", "Append a nameserver to resolv.conf. Repeatable.");
  let &flag_resolv_conf_path = cli.add_flag<cli::flag_string>(
      '\0', "dns-file", "Mount a file as /etc/resolv.conf. Overrides --dns.");
  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  if (args.empty()) {
    return make_error(
        "Missing namespace name. Try '--help' for more infomation.");
  }

  if (args.size() < 2) {
    return make_error(
        "Missing daemon command. Try '--help' for more information.");
  }

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  args.erase(args.begin());

  linux_namespace ns{ns_name};

  // Validate name before allocating any resources so the error is immediate.
  unwrap(ns.validate_name());

  ip_pool pool{ns};

  satan existing_satan{ns};
  if (!existing_satan.load().is_err()) {
    if (pid_tracker::is_alive_with_starttime(
            existing_satan.get_daemon_pid(),
            existing_satan.get_daemon_starttime()))
    {
      return make_error("Namespace '" + ns_name +
                        "' already has a running daemon (PID " +
                        std::to_string(existing_satan.get_daemon_pid()) + ")");
    }

    trace(verbosity::info, "Found stale namespace `{}`, cleaning up...",
          ns_name);

    network_configurator existing_netconf{ns, subnet{0}};
    unwrap(existing_netconf.load());
    const subnet stale_subnet{existing_netconf.get_subnet_octet()};
    ns.reset(existing_netconf);
    unused(pool.free(stale_subnet));
  }

  let subnet = unwrap(pool.allocate());
  trace(verbosity::info, "Allocated subnet: `{}`", subnet.to_string());

  let netconf = network_configurator{ns, subnet};

  cleanup_guard guard{};

  guard.add_cleanup([&ns, &netconf, &pool, &subnet]() {
    unused(ns.reset(netconf));
    unused(pool.free(subnet));
  });

  guard.add_cleanup([&netconf]() { unused(netconf.cleanup()); });
  // Call below creates network devices. Arm cleanup before the call.
  unwrap(netconf.initial_setup());

  unwrap(ns.create_dir());

  if (flag_resolv_conf_path.is_set() || !flag_dns.is_empty()) {
    if (std::filesystem::exists("/var/run/nscd/socket") ||
        std::filesystem::exists("/run/nscd/socket"))
    {
      cli::show_message(
          "warning: nscd is running; custom DNS may be ignored by the daemon");
    }
  }

  dominatrix dns(ns);
  if (flag_resolv_conf_path.is_set()) {
    unwrap(dns.set_dns_file(flag_resolv_conf_path.get_value()));
  } else if (!flag_dns.is_empty()) {
    std::vector<std::string> dns_servers;
    for (const let &server : flag_dns.values()) {
      dns_servers.push_back(server);
    }
    unwrap(dns.set_dns_servers(dns_servers));
  }

  unwrap(dns.write_configs());

  let resolv_path = unwrap(dns.get_resolv_conf_path());
  let nsswitch_path = unwrap(dns.get_nsswitch_conf_path());

  // Kill daemon on error after this point; runs first (LIFO) before network
  // teardown.
  pid_t daemon_pid = -1;
  guard.add_cleanup([&daemon_pid]() {
    if (daemon_pid != -1) {
      unused(oo_linux_syscall(kill, daemon_pid, SIGTERM));
    }
  });

  satan s{ns};
  daemon_pid = unwrap(s.spawn_daemon(args, resolv_path, nsswitch_path));
  insist(daemon_pid > 0,
         "spawn_daemon returned success without a valid daemon PID");

  unwrap(netconf.finish_setup(daemon_pid));

  s.set_daemon_pid(daemon_pid);
  unwrap(s.save());
  unwrap(netconf.save());

  guard.disarm();

  cli::show_message("Namespace `" + ns.get_name() +
                    "` is up. Daemon PID: " + std::to_string(daemon_pid) + ".");

  return ok{};
}

} // namespace oo
