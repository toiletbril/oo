#include "commands.hh"
#include "cli.hh"
#include "common.hh"
#include "debug.hh"
#include "dominatrix.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "namespace_state.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "satan.hh"
#include "signal_handler.hh"

#include <csignal>
#include <filesystem>
#include <print>
#include <sys/capability.h>
#include <unistd.h>

namespace oo {

fn cleanup_namespace(linux_namespace &ns, u8 subnet_octet,
                     std::string_view veth_host) -> void {
  network_configurator netconf(ns, subnet{subnet_octet});
  netconf.prepare_cleanup(veth_host);
  unused(netconf.cleanup());

  ip_pool pool;
  const subnet s{subnet_octet};
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

fn up(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case(
      "oo up [-options] <namespace> [--] <daemon> [daemon-args...]", "todo");

  let &flag_dns = cli.add_flag<cli::flag_many_strings>(
      '\0', "dns",
      "Add an entry to resolv.conf inside the namespace. Can be "
      "specified multiple times to add multiple DNS servers.");
  let &flag_resolv_conf_path = cli.add_flag<cli::flag_string>(
      '\0', "dns-file",
      "Path to a file to mount as /etc/resolv.conf inside the namespace. "
      "Overrides --dns if both are specified.");
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

  std::string ns_name = args[0];
  args.erase(args.begin());

  linux_namespace ns{ns_name};

  namespace_state existing_state_obj;
  let existing_state_result = existing_state_obj.load(ns);
  if (!existing_state_result.is_err()) {
    let existing_state = existing_state_result.get_value();
    if (pid_tracker::is_alive(existing_state.daemon_pid)) {
      return make_error("Namespace '" + ns_name +
                        "' already has a running daemon (PID " +
                        std::to_string(existing_state.daemon_pid) + ")");
    }

    trace(verbosity::info, "Found stale namespace `{}`, cleaning up...",
          ns_name);
    cleanup_namespace(ns, existing_state.subnet_octet,
                      existing_state.veth_host);
  }

  unwrap(ns.create_dir());

  auto pool = std::make_shared<ip_pool>();
  let subnet = unwrap(pool->allocate());
  trace(verbosity::info, "Allocated subnet: `{}`", subnet.to_string());

  auto netconf = std::make_shared<network_configurator>(ns, subnet);

  signal_handler::setup();
  auto cleanup_state_obj = std::make_shared<cleanup_state>();
  cleanup_state_obj->ns = &ns;
  cleanup_state_obj->subnet_octet = subnet.third_octet;
  cleanup_state_obj->veth_host =
      "veth-oo-" + std::to_string(subnet.third_octet);
  signal_handler::set_cleanup_state(cleanup_state_obj);

  cleanup_guard guard{};

  unwrap(netconf->initial_setup());

  dominatrix dns(ns);
  if (flag_resolv_conf_path.is_set()) {
    unwrap(dns.set_dns_file(flag_resolv_conf_path.get_value()));
  } else if (!flag_dns.is_empty()) {
    std::vector<std::string> dns_servers;
    for (const auto &server : flag_dns.values()) {
      dns_servers.push_back(server);
    }
    unwrap(dns.set_dns_servers(dns_servers));
  }

  unwrap(dns.write_configs());

  let resolv_path = unwrap(dns.get_resolv_conf_path());
  let nsswitch_path = unwrap(dns.get_nsswitch_conf_path());

  satan s{ns};
  let daemon_pid = unwrap(s.spawn_daemon(args, resolv_path, nsswitch_path));

  // Move other end of veth to the namespace.
  netconf->finish_setup(daemon_pid);

  // Persist for down/exec commands.
  namespace_state state;
  state.daemon_pid = daemon_pid;
  state.subnet_octet = subnet.third_octet;
  state.veth_host = "veth-oo-" + std::to_string(subnet.third_octet);
  state.veth_ns = "veth-ns-" + std::to_string(subnet.third_octet);
  unwrap(state.save(ns));

  guard.disarm();
  signal_handler::clear_cleanup();

  cli::show_message("Namespace `" + ns.get_name() +
                    "` is up. Daemon PID: " + std::to_string(daemon_pid) + ".");

  return ok{};
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

  std::string ns_name = args[0];
  linux_namespace ns{ns_name};

  namespace_state state_obj;
  let state_result = state_obj.load(ns);
  if (state_result.is_err()) {
    return make_error("Namespace '" + ns_name + "' not found or not running");
  }

  let state = state_result.get_value();

  // Graceful shutdown with timeout.
  if (state.daemon_pid > 0) {
    if (pid_tracker::is_alive(state.daemon_pid)) {
      trace(verbosity::info, "Sending SIGTERM to daemon PID {}",
            state.daemon_pid);
      unwrap(linux::oo_kill(state.daemon_pid, SIGTERM));

      for (int i = 0; i < 50; ++i) {
        if (!pid_tracker::is_alive(state.daemon_pid)) {
          trace(verbosity::debug, "Daemon terminated gracefully");
          break;
        }
        unwrap(linux::oo_sleep_ms(100));
      }

      if (pid_tracker::is_alive(state.daemon_pid)) {
        trace(verbosity::error, "Daemon did not terminate, sending SIGKILL");
        unwrap(linux::oo_kill(state.daemon_pid, SIGKILL));
        unwrap(linux::oo_sleep_ms(500));
      }
    } else {
      trace(verbosity::error, "Daemon PID {} not running (stale)",
            state.daemon_pid);
    }
  }

  cleanup_namespace(ns, state.subnet_octet, state.veth_host);

  trace(verbosity::info, "Namespace `{}` is down", ns_name);

  return ok{};
}

fn exec(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo exec [-options] <namespace> [--] <command> [args...]",
                   "todo");

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

  if (args.size() < 2) {
    return make_error("Missing command. Try '--help' for more information.");
  }

  std::string ns_name = args[0];
  args.erase(args.begin());

  linux_namespace ns{ns_name};
  satan s{ns};

  unwrap(s.execute(args));

  unreachable();
}

fn init(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo init [-options]", "todo");

  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  std::string exe_path =
      std::filesystem::read_symlink("/proc/self/exe").string();
  trace(verbosity::info, "Setting capabilities for: {}", exe_path);

  if (geteuid() != 0) {
    return make_error("init command must be run with sudo");
  }

  // CAP_SYS_ADMIN: Required for unshare(CLONE_NEWNET|CLONE_NEWNS).
  // CAP_NET_ADMIN: Required for network configuration (netlink, routes, etc).
  // CAP_SYS_PTRACE: Required for setns() to enter namespaces.

  cap_t caps =
      unwrap(oo_non_zero(cap_init(), "Failed to initialize capability state"));
  defer { cap_free(caps); };

  cap_value_t cap_list[3] = {CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE};

  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE, 3, cap_list,
                          CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE, 3, cap_list,
                          CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_PERMITTED, 3, cap_list,
                          CAP_SET));
  unwrap(oo_linux_syscall(cap_set_file, exe_path.c_str(), caps));

  cap_t file_caps = cap_get_file(exe_path.c_str());
  if (file_caps) {
    char *cap_text = cap_to_text(file_caps, nullptr);
    if (cap_text) {
      trace(verbosity::info, "Current capabilities: {}", cap_text);
      cap_free(cap_text);
    }
    cap_free(file_caps);
  }

  std::error_code ec;
  std::filesystem::path oo_dir = "/var/run/oo";

  if (!std::filesystem::exists(oo_dir, ec)) {
    std::filesystem::create_directories(oo_dir, ec);
    unwrap(oo_error_code(ec, "Failed to create " + oo_dir.string()));
    trace(verbosity::info, "Created {} with world-writable permissions",
          oo_dir.string());
  }

  // Set permissions (filesystem::permissions for mode, still need chown for
  // ownership)
  std::filesystem::permissions(oo_dir,
                               std::filesystem::perms::owner_all |
                                   std::filesystem::perms::group_all |
                                   std::filesystem::perms::others_all,
                               ec);
  unwrap(oo_error_code(ec, "Failed to set permissions on " + oo_dir.string()));
  trace(verbosity::info, "Updated {} permissions to 0777", oo_dir.string());

  return ok{};
}

} // namespace oo
