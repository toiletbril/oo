#include "status.hh"

#include "cli.hh"
#include "constants.hh"
#include "debug.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "network_configurator.hh"
#include "pid_tracker.hh"
#include "privilege_drop.hh"
#include "satan.hh"

#include <filesystem>
#include <optional>
#include <string>

namespace oo {

namespace {

fn pid_state(pid_t pid, u64 start_time) -> std::string {
  if (pid <= 0) {
    return "none";
  }
  const bool alive = pid_tracker::is_alive_with_start_time(pid, start_time);
  return std::to_string(pid) + (alive ? " (alive)" : " (stale)");
}

// Render the full state of one namespace. The caller has already loaded its
// process state. The network state is loaded here for the subnet IPs and is
// reported as unknown when it cannot be read.
fn describe(const std::string &name, satan &s) -> std::string {
  trace(verbosity::debug, "Reading full state of namespace `{}`", name);
  std::string out = "Namespace `" + name + "`\n";
  out += "  Daemon PID:   " +
         pid_state(s.get_daemon_pid(), s.get_daemon_start_time()) + "\n";
  std::string proxy_line =
      pid_state(s.get_proxy_pid(), s.get_proxy_start_time());
  if (s.get_proxy_pid() > 0) {
    proxy_line += s.get_proxy_backend() == proxy_backend_kind::squid
                      ? ", squid"
                      : ", builtin";
  }
  out += "  Proxy:        " + proxy_line + "\n";

  linux_namespace ns{name};
  network_configurator netconf{ns, subnet{0}};
  trace(verbosity::debug, "Loading network config for namespace `{}`", name);
  if (netconf.load().is_err()) {
    out += "  Subnet:       unknown";
    return out;
  }

  const subnet sn{netconf.get_subnet_octet()};
  out += "  Host IP:      " + sn.host_ip() + "\n";
  out += "  Namespace IP: " + sn.ns_ip();
  return out;
}

// Render one summary line for the listing, or nothing when the caller may not
// see this namespace. Reports a stale marker when the directory has no readable
// process state. A stale directory has no recorded owner, so only root sees it.
fn summarize(const std::string &name, uid_t invoking_uid)
    -> std::optional<std::string> {
  trace(verbosity::debug, "Loading process state for namespace `{}`", name);
  linux_namespace ns{name};
  passwd pw;
  satan s{ns, pw};
  if (s.load().is_err()) {
    if (invoking_uid != 0) {
      return std::nullopt;
    }
    return name + ": stale (no state)";
  }

  if (!s.is_accessible_by(invoking_uid)) {
    return std::nullopt;
  }

  const bool daemon_alive = pid_tracker::is_alive_with_start_time(
      s.get_daemon_pid(), s.get_daemon_start_time());
  const bool proxy_alive =
      s.get_proxy_pid() > 0 && pid_tracker::is_alive_with_start_time(
                                   s.get_proxy_pid(), s.get_proxy_start_time());

  std::string line = name;
  line += daemon_alive ? ": daemon is alive" : ": daemon is dead";
  line += proxy_alive ? ", proxy is alive" : ", no proxy";

  network_configurator netconf{ns, subnet{0}};
  if (!netconf.load().is_err()) {
    const subnet sn{netconf.get_subnet_octet()};
    line += ", " + sn.ns_ip();
  }

  return line;
}

fn list_all() -> error_or<ok> {
  trace(verbosity::info, "Enumerating namespaces under {}",
        constants::OO_RUN_DIR);

  // status never elevates, so the real invoking uid is the live process uid.
  // Root sees every namespace; a normal user sees only the ones they own.
  const uid_t invoking_uid = ::getuid();

  std::error_code ec;
  if (!std::filesystem::exists(constants::OO_RUN_DIR, ec) || ec) {
    cli::show_message("No namespaces.");
    return ok{};
  }

  // Iterate with the error_code-taking increment rather than a range-for. The
  // range-for would call the throwing operator++, which aborts the process
  // under -fno-exceptions when a concurrent `oo down` removes an entry between
  // increments.
  bool any = false;
  std::error_code it_ec;
  let it = std::filesystem::directory_iterator(constants::OO_RUN_DIR, it_ec);
  if (it_ec) {
    return make_error("Failed to enumerate " +
                      std::string{constants::OO_RUN_DIR} + ": " +
                      it_ec.message());
  }
  const std::filesystem::directory_iterator end{};
  while (it != end) {
    std::error_code st_ec;
    if (it->is_directory(st_ec) && !st_ec) {
      if (let line = summarize(it->path().filename().string(), invoking_uid)) {
        any = true;
        cli::show_message(*line);
      }
    }
    it.increment(it_ec);
    if (it_ec) {
      return make_error("Failed to enumerate " +
                        std::string{constants::OO_RUN_DIR} + ": " +
                        it_ec.message());
    }
  }

  if (!any) {
    cli::show_message("No namespaces.");
  }

  return ok{};
}

} // namespace

fn status(cli::cli &&cli) -> error_or<ok> {
  cli.add_use_case("oo status [namespace]", "Show namespace state.");

  let &flag_help = cli.add_flag<cli::flag_boolean>('\0', "help", "Print help.");

  let args = unwrap(cli.parse_args());

  if (flag_help.is_enabled()) {
    cli.show_help();
    return ok{};
  }

  if (args.empty()) {
    return list_all();
  }

  const std::string &ns_name = args[0];
  linux_namespace ns{ns_name};
  passwd pw;
  satan s{ns, pw};
  trace(verbosity::info, "Loading process state for namespace `{}`", ns_name);
  if (s.load().is_err()) {
    return make_error("Namespace '" + ns_name + "' is not running");
  }

  if (!s.is_accessible_by(pw.get_invoking_uid())) {
    return make_error("Namespace '" + ns_name + "' is owned by another user");
  }

  cli::show_message(describe(ns_name, s));

  return ok{};
}

} // namespace oo
