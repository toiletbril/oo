#include "touch.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "dominatrix.hh"
#include "foreground.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"
#include "proxy.hh"
#include "satan.hh"
#include "signal_handler.hh"

#include <climits>
#include <csignal>
#include <string>
#include <unistd.h>
#include <vector>

namespace oo {

namespace {

constexpr usize STOP_TIMEOUT_S = 10;

// Stop a process group the same way `down` does. The caller signals the group
// leader's pid negated, so the whole group receives it. Aliveness is checked by
// the caller before this runs. Kills are best effort so a transient errno never
// aborts the surrounding teardown.
fn stop_process_group(pid_t group) -> void {
  trace(verbosity::info, "Sending SIGTERM to group {}", group);
  unused(linux::oo_kill(-group, SIGTERM));

  let iterations =
      STOP_TIMEOUT_S * 1000 / constants::GRACEFUL_SHUTDOWN_SLEEP_MS;
  for (usize i = 0; i < iterations; ++i) {
    if (::kill(-group, 0) != 0) {
      break;
    }
    unused(linux::oo_sleep_ms(constants::GRACEFUL_SHUTDOWN_SLEEP_MS));
  }

  if (::kill(-group, 0) == 0) {
    trace(verbosity::error, "Group {} did not terminate, sending SIGKILL",
          group);
    unused(linux::oo_kill(-group, SIGKILL));
    // Give the kernel a moment to reap the group and release its namespace and
    // veth before the caller rebuilds them, the same settle `down` performs.
    unused(linux::oo_sleep_ms(constants::FORCEFUL_SHUTDOWN_SLEEP_MS));
  }
}

} // namespace

fn touch(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo touch [-options] <namespace> [--] [daemon command]",
                   "Attach to or mess with running namespace.");

  let &flag_shutdown_proxy = cli.add_flag<cli::flag_boolean>(
      '\0', "shutdown-proxy", "Stop the running proxy.");
  let &flag_restart_proxy = cli.add_flag<cli::flag_boolean>(
      '\0', "restart-proxy",
      "Stop the running proxy and start a new one. Requires --http-proxy.");
  let &flag_relaunch = cli.add_flag<cli::flag_boolean>(
      '\0', "relaunch-daemon",
      "Rebuild the network and respawn the daemon. Keeps the same subnet. "
      "Requires the daemon command after '--'.");
  let &flag_set_name = cli.add_flag<cli::flag_string>(
      '\0', "set-name",
      "Rename the namespace. Valid only together with --relaunch-daemon.");
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
      "directory.");
  let &flag_no_daemon_dns = cli.add_flag<cli::flag_boolean>(
      '\0', "no-daemon-dns",
      "Run the daemon itself with the host's /etc/resolv.conf, but still "
      "apply --dns/--dns-file to commands started with 'oo exec'.");
  let &flag_http_proxy = cli.add_flag<cli::flag_string>(
      '\0', "http-proxy",
      "Start an HTTP/HTTPS forward proxy bound to <ip>:<port>. Reachable from "
      "the host at the namespace IP. The proxy is open to any client that can "
      "reach that address.");
  let &flag_proxy_backend = cli.add_flag<cli::flag_string>(
      '\0', "http-proxy-backend",
      "Proxy implementation for --http-proxy: 'builtin' (default) or 'squid'.");
  let &flag_background = cli.add_flag<cli::flag_boolean>(
      'd', "background",
      "Detach and return immediately. Only meaningful with "
      "--relaunch-daemon. Default for relaunch is to stay attached, tail the "
      "daemon output to this terminal, and tear the namespace down when the "
      "daemon exits.");
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

  const bool want_relaunch = flag_relaunch.is_enabled();
  const bool want_shutdown = flag_shutdown_proxy.is_enabled();
  const bool want_restart = flag_restart_proxy.is_enabled();
  const bool want_proxy = flag_http_proxy.is_set();
  const bool want_setname = flag_set_name.is_set();
  const bool want_attach = !want_relaunch && !want_shutdown && !want_restart &&
                           !want_proxy && !want_setname;

  if (want_setname && !want_relaunch) {
    return make_error("--set-name is only valid together with "
                      "--relaunch-daemon.");
  }

  if (flag_proxy_backend.is_set() && !want_proxy) {
    return make_error("--http-proxy-backend requires --http-proxy.");
  }

  if (flag_background.is_enabled() && !want_relaunch) {
    return make_error(
        "--background is only valid together with --relaunch-daemon.");
  }

  endpoint proxy_bind{};
  proxy_backend_kind proxy_backend = proxy_backend_kind::builtin;
  if (want_proxy) {
    proxy_bind = unwrap(endpoint::parse(flag_http_proxy.get_value()));
    if (flag_proxy_backend.is_set()) {
      proxy_backend =
          unwrap(parse_proxy_backend(flag_proxy_backend.get_value()));
    }
  }

  const std::string ns_name = args[0];

  unwrap(ensure_runtime_dir_exists());

  // relaunch mode.
  if (want_relaunch) {
    if (want_shutdown || want_restart) {
      return make_error("--shutdown-proxy and --restart-proxy cannot combine "
                        "with --relaunch-daemon.");
    }

    const std::vector<std::string> daemon_argv(args.begin() + 1, args.end());
    if (daemon_argv.empty()) {
      return make_error("Missing daemon command for --relaunch-daemon. "
                        "Try '--help' for more information.");
    }

    // Capture the caller's cwd before any privilege drop, like `up`. The
    // signalling and the su below do not chdir, so reading it here is safe.
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

    bool prefix_overridden = false;
    u8 subnet_prefix = constants::DEFAULT_SUBNET_PREFIX_LEN;
    if (flag_subnet_prefix.is_set()) {
      const std::string prefix_str{flag_subnet_prefix.get_value()};
      char *end = nullptr;
      const u64 parsed = strtoul(prefix_str.c_str(), &end, 10);
      if (end == prefix_str.c_str() || *end != '\0') {
        return make_error("The --subnet-prefix value '" + prefix_str +
                          "' is not a valid number");
      }
      if (parsed < constants::MIN_SUBNET_PREFIX_LEN ||
          parsed > constants::MAX_SUBNET_PREFIX_LEN) {
        return make_error("--subnet-prefix must be between " +
                          std::to_string(constants::MIN_SUBNET_PREFIX_LEN) +
                          " and " +
                          std::to_string(constants::MAX_SUBNET_PREFIX_LEN));
      }
      subnet_prefix = static_cast<u8>(parsed);
      prefix_overridden = true;
    }

    const std::string &old_name = ns_name;
    const std::string new_name =
        want_setname ? std::string{flag_set_name.get_value()} : ns_name;

    linux_namespace old_ns{old_name};
    linux_namespace target_ns{new_name};
    unwrap(target_ns.validate_name());

    trace(verbosity::info, "Relaunching namespace `{}` as `{}`", old_name,
          new_name);

    passwd pw;
    satan old_s{old_ns, pw};
    if (old_s.load().is_err()) {
      return make_error("Namespace '" + old_name + "' is not running");
    }

    network_configurator old_netconf{old_ns, subnet{0}};
    if (old_netconf.load().is_err()) {
      return make_error("Namespace '" + old_name + "' is not running");
    }
    const u8 keep_octet = old_netconf.get_subnet_octet();

    // Keep the namespace's existing prefix unless the caller overrides it, so a
    // relaunch preserves the netmask, not just the third octet.
    if (!prefix_overridden) {
      subnet_prefix = old_netconf.get_subnet_prefix();
    }

    if (new_name != old_name && target_ns.dir_exists()) {
      return make_error("Namespace '" + new_name +
                        "' already exists. Choose another name.");
    }

    // Capture DNS configuration while still the invoking user, since a
    // --dns-file may be readable only by that user. The files are written into
    // the target namespace directory by write_configs after the drop.
    dominatrix dns(target_ns);
    if (flag_resolv_conf_path.is_set()) {
      unwrap(dns.set_dns_file(flag_resolv_conf_path.get_value()));
    } else if (!flag_dns.is_empty()) {
      std::vector<std::string> dns_servers;
      for (const let &server : flag_dns.values()) {
        dns_servers.push_back(server);
      }
      unwrap(dns.set_dns_servers(dns_servers));
    }

    // SECURITY: the daemon and proxy are owned by the invoking user, so stop
    // them as that user before switching to oorunner.
    if (old_s.get_daemon_pid() > 0 &&
        pid_tracker::is_alive_with_start_time(old_s.get_daemon_pid(),
                                              old_s.get_daemon_start_time())) {
      stop_process_group(old_s.get_daemon_pid());
    }
    if (old_s.get_proxy_pid() > 0 &&
        pid_tracker::is_alive_with_start_time(old_s.get_proxy_pid(),
                                              old_s.get_proxy_start_time())) {
      stop_process_group(old_s.get_proxy_pid());
    }

    unwrap(pw.su_oorunner());

    // On rename, transfer the kept subnet's ownership to the new name before
    // anything is destroyed. If the reassign fails, the old namespace and its
    // subnet allocation are still intact rather than orphaned.
    if (new_name != old_name) {
      trace(verbosity::info, "Reassigning subnet from `{}` to `{}`", old_name,
            new_name);
      ip_pool pool{target_ns};
      unwrap(pool.reassign(subnet{keep_octet}, old_name));
    }

    // Tear down the old network and directory under the old name. The subnet
    // allocation is intentionally kept so the rebuilt namespace reuses the same
    // IP.
    trace(verbosity::info, "Tearing down old network for namespace `{}`",
          old_name);
    unused(old_ns.reset(old_netconf));

    const subnet sn{keep_octet, subnet_prefix};
    network_configurator netconf{target_ns, sn};

    // Declared before the guard so they outlive it; the cleanup lambdas capture
    // them by reference and locals are destroyed in reverse order.
    pid_t daemon_pid = -1;
    pid_t proxy_pid = -1;

    cleanup_guard guard{};

    // On failure the namespace cannot be restored to its previous daemon, so
    // roll back to a clean state: tear down the new network and free the kept
    // subnet rather than leaking the allocation.
    guard.add_cleanup([&target_ns, &netconf, keep_octet]() {
      unused(target_ns.reset(netconf));
      ip_pool pool{target_ns};
      unused(pool.free(subnet{keep_octet}));
    });

    unwrap(target_ns.create_dir());

    guard.add_cleanup([&netconf]() { unused(netconf.cleanup()); });
    unwrap(netconf.initial_setup());

    if (flag_resolv_conf_path.is_set() || !flag_dns.is_empty()) {
      if (std::filesystem::exists("/var/run/nscd/socket") ||
          std::filesystem::exists("/run/nscd/socket")) {
        cli::show_message(
            "warning: nscd is running; custom DNS may be ignored by the "
            "daemon");
      }
    }

    unwrap(dns.write_configs());

    let resolv_path = unwrap(dns.get_resolv_conf_path());
    let nsswitch_path = unwrap(dns.get_nsswitch_conf_path());

    guard.add_cleanup([&daemon_pid]() {
      if (daemon_pid > 0) {
        unused(linux::oo_kill(-daemon_pid, SIGKILL));
      }
    });

    satan s{target_ns, pw};
    trace(verbosity::info, "Spawning daemon in namespace `{}`", new_name);
    daemon_pid =
        unwrap(s.spawn_daemon(daemon_argv, start_cwd, resolv_path,
                              nsswitch_path, flag_no_daemon_dns.is_enabled()));

    s.set_daemon_start_time(unwrap(pid_tracker::read_start_time(daemon_pid)));

    unwrap(netconf.finish_setup(daemon_pid));

    s.set_daemon_pid(daemon_pid);
    s.set_dns_on_monitor(flag_no_daemon_dns.is_enabled());

    if (want_proxy) {
      guard.add_cleanup([&proxy_pid]() {
        if (proxy_pid > 0) {
          unused(linux::oo_kill(-proxy_pid, SIGKILL));
        }
      });
      trace(verbosity::info, "Spawning proxy in namespace `{}`", new_name);
      proxy_pid = unwrap(s.spawn_proxy(proxy_bind, proxy_backend, sn.ns_ip(),
                                       netconf.get_default_iface()));
      s.set_proxy_pid(proxy_pid);
      s.set_proxy_start_time(unwrap(pid_tracker::read_start_time(proxy_pid)));
      s.set_proxy_backend(proxy_backend);
    }

    unwrap(s.save());
    unwrap(netconf.save());

    guard.disarm();

    // Reap orphan namespaces, like up and down do. Run only after the new
    // daemon is live and saved so the relaunched namespace is not itself seen
    // as an orphan.
    unused(s.sweep_orphans());

    cli::show_message("Namespace `" + new_name + "` relaunched. Daemon PID: " +
                      std::to_string(daemon_pid) + ".");

    if (want_proxy) {
      cli::show_message("HTTP proxy listening on " + sn.ns_ip() + ":" +
                        std::to_string(proxy_bind.port) +
                        ". Proxy PID: " + std::to_string(proxy_pid) + ".");
    }

    if (flag_background.is_enabled()) {
      return ok{};
    }

    return attach_and_supervise(daemon_pid, s.get_daemon_start_time(),
                                s.get_proxy_pid(), s.get_proxy_start_time(),
                                target_ns, netconf, sn, pw, false);
  }

  // attach mode. No action flag means attach to the existing daemon, tail
  // its log files to this terminal, and tear the namespace down when the
  // daemon exits.
  if (want_attach) {
    trace(verbosity::info, "Attaching to daemon of namespace `{}`", ns_name);
    linux_namespace ns{ns_name};
    unwrap(ns.validate_name());
    passwd pw;
    satan s{ns, pw};
    if (s.load().is_err()) {
      return make_error("Namespace '" + ns_name + "' is not running");
    }
    if (!pid_tracker::is_alive_with_start_time(s.get_daemon_pid(),
                                               s.get_daemon_start_time())) {
      return make_error("Namespace '" + ns_name + "' is not running");
    }

    network_configurator netconf{ns, subnet{0}};
    if (netconf.load().is_err()) {
      return make_error("Namespace '" + ns_name + "' is not running");
    }
    const subnet sn{netconf.get_subnet_octet(), netconf.get_subnet_prefix()};

    unwrap(pw.su_oorunner());

    return attach_and_supervise(s.get_daemon_pid(), s.get_daemon_start_time(),
                                s.get_proxy_pid(), s.get_proxy_start_time(), ns,
                                netconf, sn, pw, true);
  }

  // proxy mode.
  if (want_restart && !want_proxy) {
    return make_error("--restart-proxy requires --http-proxy.");
  }
  if (want_restart && want_shutdown) {
    return make_error("--restart-proxy cannot combine with --shutdown-proxy.");
  }
  if (want_shutdown && want_proxy) {
    return make_error("--shutdown-proxy cannot combine with --http-proxy. Use "
                      "--restart-proxy to replace a running proxy.");
  }

  linux_namespace ns{ns_name};
  passwd pw;
  satan s{ns, pw};
  if (s.load().is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  const bool daemon_alive = pid_tracker::is_alive_with_start_time(
      s.get_daemon_pid(), s.get_daemon_start_time());
  const bool proxy_alive =
      s.get_proxy_pid() > 0 && pid_tracker::is_alive_with_start_time(
                                   s.get_proxy_pid(), s.get_proxy_start_time());

  if (want_proxy && !want_restart && proxy_alive) {
    return make_error(
        "Namespace '" + ns_name + "' already has a running proxy (PID " +
        std::to_string(s.get_proxy_pid()) +
        "). Use --restart-proxy to replace it, or --shutdown-proxy first.");
  }

  if (want_proxy && !daemon_alive) {
    return make_error("Namespace '" + ns_name + "' has no running daemon");
  }

  // SECURITY: the proxy is owned by the invoking user, so stop it as that user
  // before switching to oorunner for the state write below.
  if ((want_shutdown || want_restart) && proxy_alive) {
    stop_process_group(s.get_proxy_pid());
  }

  unwrap(pw.su_oorunner());

  // Persist the stop before spawning a replacement. A restart that kills the
  // old proxy and then fails to spawn the new one must not leave the dead pid
  // recorded in the state file.
  if (want_shutdown || want_restart) {
    s.set_proxy_pid(0);
    s.set_proxy_start_time(0);
    unwrap(s.save());
  }

  pid_t proxy_pid = -1;
  if (want_proxy) {
    // Resolve the host-reachable namespace IP for the proxy label and the
    // message, so both show the address to connect to rather than 0.0.0.0.
    std::string ns_ip;
    std::string default_iface;
    network_configurator netconf{ns, subnet{0}};
    if (!netconf.load().is_err()) {
      ns_ip = subnet{netconf.get_subnet_octet()}.ns_ip();
      default_iface = std::string{netconf.get_default_iface()};
    }

    trace(verbosity::info, "Spawning proxy in namespace `{}`", ns_name);
    proxy_pid =
        unwrap(s.spawn_proxy(proxy_bind, proxy_backend, ns_ip, default_iface));
    s.set_proxy_pid(proxy_pid);
    s.set_proxy_start_time(unwrap(pid_tracker::read_start_time(proxy_pid)));
    s.set_proxy_backend(proxy_backend);
    unwrap(s.save());

    const std::string where =
        ns_ip.empty() ? proxy_bind.to_string()
                      : ns_ip + ":" + std::to_string(proxy_bind.port);
    cli::show_message("HTTP proxy listening on " + where +
                      ". Proxy PID: " + std::to_string(proxy_pid) + ".");
  } else {
    cli::show_message("Proxy stopped for namespace `" + ns_name + "`.");
  }

  return ok{};
}

} // namespace oo
