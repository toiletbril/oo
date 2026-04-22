#include "up.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "dominatrix.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"
#include "satan.hh"
#include "signal_handler.hh"

#include <csignal>

namespace oo {

fn up(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case(
      "oo up [-options] <namespace> [--] <daemon> [daemon-args...]",
      "Start a daemon in a new network namespace.");

  let &flag_dns = cli.add_flag<cli::flag_many_strings>(
      '\0', "dns", "Append a nameserver to resolv.conf. Repeatable.");
  let &flag_resolv_conf_path = cli.add_flag<cli::flag_string>(
      '\0', "dns-file", "Mount a file as /etc/resolv.conf. Overrides --dns.");
  let &flag_subnet_prefix = cli.add_flag<cli::flag_string>(
      '\0', "subnet-prefix",
      "Subnet prefix length, from 16 to 30 (default 30). Wider prefixes "
      "overlap across namespaces.");
  let &flag_at_root = cli.add_flag<cli::flag_boolean>(
      '\0', "at-root",
      "Start the daemon with cwd=/ instead of the caller's current "
      "directory. Use when the invoking cwd may disappear or is not "
      "reachable inside the namespace's mount ns.");
  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  // Capture the caller's cwd before any privilege drop or chdir. This is
  // the cwd the daemon will land in unless --at-root is given. Done here
  // because anything below may fork/chdir and change the reading.
  std::string start_cwd;
  if (flag_at_root.is_enabled()) {
    start_cwd = "/";
  } else {
    char cwd_buf[PATH_MAX];
    if (::getcwd(cwd_buf, sizeof(cwd_buf)) == nullptr) {
      return make_error("Could not read current working directory. "
                        "Pass --at-root to start the daemon at /.");
    }
    start_cwd = cwd_buf;
  }

  if (args.empty()) {
    return make_error(
        "Missing namespace name. Try '--help' for more infomation.");
  }

  if (args.size() < 2) {
    return make_error(
        "Missing daemon command. Try '--help' for more information.");
  }

  u8 subnet_prefix = constants::DEFAULT_SUBNET_PREFIX_LEN;
  if (flag_subnet_prefix.is_set()) {
    const std::string prefix_str{flag_subnet_prefix.get_value()};
    char *end = nullptr;
    const u64 parsed = strtoul(prefix_str.c_str(), &end, 10);
    if (end == prefix_str.c_str() || *end != '\0') {
      return make_error("Invalid --subnet-prefix value: " + prefix_str);
    }
    if (parsed < constants::MIN_SUBNET_PREFIX_LEN ||
        parsed > constants::MAX_SUBNET_PREFIX_LEN) {
      return make_error("--subnet-prefix must be between " +
                        std::to_string(constants::MIN_SUBNET_PREFIX_LEN) +
                        " and " +
                        std::to_string(constants::MAX_SUBNET_PREFIX_LEN));
    }
    subnet_prefix = static_cast<u8>(parsed);
  }

  passwd pw;
  unwrap(pw.su_oorunner());

  unwrap(ensure_runtime_dir_exists());

  std::string ns_name = args[0];
  args.erase(args.begin());

  linux_namespace ns{ns_name};
  unwrap(ns.validate_name());

  ip_pool pool{ns};

  satan existing_satan{ns, pw};
  if (!existing_satan.load().is_err()) {
    if (pid_tracker::is_alive_with_start_time(
            existing_satan.get_daemon_pid(),
            existing_satan.get_daemon_start_time())) {
      return make_error("Namespace '" + ns_name +
                        "' already has a running daemon (PID " +
                        std::to_string(existing_satan.get_daemon_pid()) + ")");
    }

    trace(verbosity::info, "Found stale namespace `{}`, cleaning up...",
          ns_name);

    network_configurator existing_netconf{ns, subnet{0}};
    unwrap(existing_netconf.load());
    const subnet stale_subnet{existing_netconf.get_subnet_octet()};
    unused(ns.reset(existing_netconf));
    unused(pool.free(stale_subnet));
  } else if (ns.dir_exists()) {
    return make_error(
        "Namespace '" + ns_name +
        "' directory exists but has no oo state; refusing to adopt. "
        "Remove " +
        (std::filesystem::path{constants::OO_RUN_DIR} / ns_name).string() +
        " if you want to reuse the name.");
  }

  unused(existing_satan.sweep_orphans());

  let allocated = unwrap(pool.allocate());
  let subnet = oo::subnet{allocated.get_third_octet(), subnet_prefix};

  let netconf = network_configurator{ns, subnet};

  // Create the namespace directory before the first host-visible mutation
  // so the netfilter cleanup log has a home to land in. Rule insertion in
  // initial_setup() persists cleanup intent to this directory.
  unwrap(ns.create_dir());

  cleanup_guard guard{};

  guard.add_cleanup([&ns, &netconf, &pool, &subnet]() {
    unused(ns.reset(netconf));
    unused(pool.free(subnet));
  });

  guard.add_cleanup([&netconf]() { unused(netconf.cleanup()); });
  // Call below creates network devices. Arm cleanup before the call.
  unwrap(netconf.initial_setup());

  if (flag_resolv_conf_path.is_set() || !flag_dns.is_empty()) {
    if (std::filesystem::exists("/var/run/nscd/socket") ||
        std::filesystem::exists("/run/nscd/socket")) {
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

  pid_t daemon_pid = -1;
  guard.add_cleanup(
      [&daemon_pid]() { unused(linux::oo_kill(daemon_pid, SIGKILL)); });

  satan s{ns, pw};
  daemon_pid =
      unwrap(s.spawn_daemon(args, start_cwd, resolv_path, nsswitch_path));

  s.set_daemon_start_time(unwrap(pid_tracker::read_start_time(daemon_pid)));

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
