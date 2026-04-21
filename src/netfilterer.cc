#include "netfilterer.hh"

#include "caps.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace oo {

fn netfilterer_backend::run_privileged(const std::vector<std::string> &argv)
    -> error_or<ok>
{
  insist(!argv.empty() && !argv[0].empty(),
         "run_privileged requires argv[0] as the absolute backend path");

  pid_t pid = unwrap(linux::oo_fork());

  if (pid == 0) {
    let su = linux::oo_setuid(0);
    if (su.is_err()) {
      trace(verbosity::error, "setuid(0) failed: {}",
            su.get_error().get_reason());
      exit(1);
    }
    insist(::getuid() == 0 && ::geteuid() == 0,
           "setuid(0) returned success but uid is not root");
    trace(verbosity::debug, "setuid(0) ok, executing {}", argv[0]);

    // SECURITY: Drop all inherited capabilities before exec. uid=0 is
    // sufficient for iptables/nftables to open their locks and run their
    // root checks; no DAC-override or any other capability is needed in
    // the child. The parent holds CAP_SETUID which authorized the
    // setuid(0) above. A failure here MUST be fatal: the child is already
    // uid 0 with the full permitted set, and an exec of iptables-legacy
    // while still holding caps would hand those caps to a binary that
    // inherits the attacker's environment.
    if (let r = caps::drop_for_exec(); r.is_err()) {
      trace(verbosity::error, "drop_for_exec failed in uid-0 child: {}",
            r.get_error().get_reason());
      exit(1);
    }

    // SECURITY: wipe every inherited environment variable before exec as
    // uid 0. The parent env is attacker-controlled; LD_PRELOAD,
    // LD_LIBRARY_PATH, LD_AUDIT, LOCPATH, or IFS in a uid-0 child would
    // let the invoker inject code into the iptables-legacy process. A
    // minimal allowlist is then set so the binary can still locate its
    // own shared objects under a vanilla loader policy.
    if (::clearenv() != 0) {
      trace(verbosity::error, "clearenv failed in uid-0 child");
      exit(1);
    }
    unused(
        oo_linux_syscall(setenv, "PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1));
    unused(oo_linux_syscall(setenv, "LANG", "C", 1));
    unused(oo_linux_syscall(setenv, "LC_ALL", "C", 1));

    // SECURITY: close every inherited FD past stderr before exec. Most of
    // them are already O_CLOEXEC (see oo_pipe, log file opens), but a
    // future caller may forget, and iptables-legacy as uid 0 is not a
    // process that should have arbitrary FDs to our state directory.
    // SYS_close_range is Linux 5.9+; ENOSYS on older kernels is benign.
    unused(::syscall(SYS_close_range, 3U, ~0U, 0U));

    // SECURITY: Use absolute path (argv[0]) that the backend detected at
    // construction time. Never a bare command name to prevent
    // PATH-hijacking of this setuid(0) child process.
    unused(linux::oo_exec(argv));
    exit(1);
  }

  int status;
  unwrap(linux::oo_waitpid(pid, &status, 0));

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return make_error(argv[0] + " command failed");
  }

  return ok{};
}

fn netfilterer_backend::persist_cleanup(const std::vector<std::string> &argv)
    -> error_or<ok>
{
  insist(!argv.empty(), "persist_cleanup requires a non-empty argv");

  let ns_path = unwrap(m_ns.get_path());
  let log_path = ns_path / NETFILTER_LOG_FILE;

  std::error_code ec;
  if (!std::filesystem::exists(ns_path, ec) || ec) {
    return make_error("Namespace directory missing for netfilter log: " +
                      ns_path.string());
  }

  std::ofstream f(log_path, std::ios::app);
  if (!f.is_open()) {
    return make_error("Could not open netfilter log " + log_path.string());
  }
  for (usize i = 0; i < argv.size(); ++i) {
    if (i != 0) f << ' ';
    f << argv[i];
  }
  f << '\n';
  f.flush();
  if (!f.good()) {
    return make_error("Failed to write netfilter log " + log_path.string());
  }

  m_cleanup_cmds.push_back(argv);
  return ok{};
}

fn netfilterer_backend::load_persisted_cleanups()
    -> error_or<std::vector<std::vector<std::string>>>
{
  let ns_path = unwrap(m_ns.get_path());
  let log_path = ns_path / NETFILTER_LOG_FILE;

  std::vector<std::vector<std::string>> out;
  std::error_code ec;
  if (!std::filesystem::exists(log_path, ec) || ec) {
    return out;
  }

  std::ifstream f(log_path);
  if (!f.is_open()) {
    return make_error("Could not open netfilter log " + log_path.string());
  }

  std::string line;
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    std::vector<std::string> argv;
    std::istringstream iss(line);
    std::string token;
    while (iss >> token)
      argv.push_back(std::move(token));
    if (!argv.empty()) out.push_back(std::move(argv));
  }

  return out;
}

fn netfilterer_backend::remove_persisted_cleanups() -> void
{
  let ns_path_r = m_ns.get_path();
  if (ns_path_r.is_err()) return;
  let log_path = ns_path_r.get_value() / NETFILTER_LOG_FILE;
  std::error_code ec;
  std::filesystem::remove(log_path, ec);
  if (ec) {
    trace(verbosity::error, "Failed to remove netfilter log {}: {}",
          log_path.string(), ec.message());
  }
}

fn iptables_legacy_backend::setup_nat(std::string_view host_iface,
                                      std::string_view subnet) -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface, subnet);
  const std::string subnet_str{subnet};
  const std::string iface_str{host_iface};

  // SECURITY: persist the cleanup argv BEFORE inserting the rule. If the
  // process dies between persist and insert, cleanup will attempt a
  // harmless -D of a non-existent rule. If it dies between insert and
  // persist, the rule leaks and a later sweep must remove it; the log
  // file is the on-disk source of truth for rules we own.
  unwrap(
      persist_cleanup({m_backend_path, "-t", "nat", "-D", "POSTROUTING", "-s",
                       subnet_str, "-o", iface_str, "-j", "MASQUERADE"}));

  unwrap(run_privileged({m_backend_path, "-t", "nat", "-A", "POSTROUTING", "-s",
                         subnet_str, "-o", iface_str, "-j", "MASQUERADE"}));

  trace(verbosity::info, "Setup NAT for {} via {}", subnet, host_iface);

  return ok{};
}

fn iptables_legacy_backend::setup_forward(std::string_view host_iface)
    -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface);
  const std::string iface_str{host_iface};

  unwrap(persist_cleanup(
      {m_backend_path, "-D", "FORWARD", "-i", iface_str, "-j", "ACCEPT"}));
  unwrap(run_privileged(
      {m_backend_path, "-A", "FORWARD", "-i", iface_str, "-j", "ACCEPT"}));

  unwrap(persist_cleanup(
      {m_backend_path, "-D", "FORWARD", "-o", iface_str, "-j", "ACCEPT"}));
  unwrap(run_privileged(
      {m_backend_path, "-A", "FORWARD", "-o", iface_str, "-j", "ACCEPT"}));

  trace(verbosity::info, "Setup FORWARD rules for {}", host_iface);

  return ok{};
}

fn iptables_legacy_backend::cleanup() -> error_or<ok>
{
  if (m_cleaned_up) {
    return ok{};
  }

  // Reconcile against on-disk state. The in-memory list may be empty after
  // reconstruction following a crash; the log is authoritative.
  if (let r = load_persisted_cleanups(); !r.is_err()) {
    m_cleanup_cmds = r.get_value();
  } else {
    trace(verbosity::error, "Failed to load persisted netfilter log: {}",
          r.get_error().get_reason());
  }

  // SECURITY: every token in an argv comes from internal state. The
  // persisted log is only written by persist_cleanup, which takes argvs
  // built here from validated interface names and subnet strings. argv[0]
  // is always the absolute backend path.
  for (const let &argv : m_cleanup_cmds) {
    if (argv.empty()) continue;
    if (let r = run_privileged(argv); r.is_err()) {
      trace(verbosity::error, "Cleanup command failed: {}",
            r.get_error().get_reason());
    }
  }

  trace(verbosity::debug, "Cleaned up iptables rules");
  m_cleanup_cmds.clear();
  remove_persisted_cleanups();
  m_cleaned_up = true;

  return ok{};
}

fn nftables_backend::setup_nat(std::string_view host_iface,
                               std::string_view subnet) -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface, subnet);
  const std::string subnet_str{subnet};
  const std::string iface_str{host_iface};

  unwrap(run_privileged({m_backend_path, "add", "rule", "ip", "nat",
                         "postrouting", "oifname", iface_str, "ip", "saddr",
                         subnet_str, "masquerade"}));

  // Nftables requires rule handles for precise deletion.
  trace(verbosity::info, "Setup NAT for {} via {} (nftables)", subnet,
        host_iface);

  return ok{};
}

fn nftables_backend::setup_forward(std::string_view host_iface) -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface);
  const std::string iface_str{host_iface};

  unwrap(run_privileged({m_backend_path, "add", "rule", "ip", "filter",
                         "forward", "iifname", iface_str, "accept"}));
  unwrap(run_privileged({m_backend_path, "add", "rule", "ip", "filter",
                         "forward", "oifname", iface_str, "accept"}));

  trace(verbosity::info, "Setup FORWARD rules for {} (nftables)", host_iface);

  return ok{};
}

fn nftables_backend::cleanup() -> error_or<ok>
{
  if (m_cleaned_up) {
    return ok{};
  }

  // Nftables rule-handle tracking is not implemented. Any rule inserted
  // by setup_nat or setup_forward remains on the host. This is a known
  // asymmetry against iptables_legacy_backend; prefer iptables-legacy
  // until an nft parser for `nft -a list ruleset` lands here.
  trace(verbosity::error,
        "WARNING: nftables backend cannot clean up its rules; inspect with "
        "`nft list ruleset` and remove manually");
  m_cleanup_cmds.clear();
  m_cleaned_up = true;

  return ok{};
}

fn netfilterer::detect(linux_namespace &ns)
    -> std::unique_ptr<netfilterer_backend>
{
  // SECURITY: Store the absolute path so all exec calls use it directly.
  // Never use a bare command name with execvp; a compromised PATH combined
  // with a setuid(0) child would allow arbitrary root code execution.
  if (std::filesystem::exists(constants::IPTABLES_LEGACY_SBIN_PATH)) {
    return std::make_unique<iptables_legacy_backend>(
        ns, std::string{constants::IPTABLES_LEGACY_SBIN_PATH});
  }
  if (std::filesystem::exists(constants::IPTABLES_LEGACY_BIN_PATH)) {
    return std::make_unique<iptables_legacy_backend>(
        ns, std::string{constants::IPTABLES_LEGACY_BIN_PATH});
  }
  if (std::filesystem::exists(constants::NFT_SBIN_PATH)) {
    return std::make_unique<nftables_backend>(
        ns, std::string{constants::NFT_SBIN_PATH});
  }
  if (std::filesystem::exists(constants::NFT_BIN_PATH)) {
    return std::make_unique<nftables_backend>(
        ns, std::string{constants::NFT_BIN_PATH});
  }
  return nullptr;
}

netfilterer::netfilterer(linux_namespace &ns) : m_impl(detect(ns))
{
  trace(verbosity::info, "Using firewall backend: {}",
        m_impl ? (dynamic_cast<iptables_legacy_backend *>(m_impl.get())
                      ? "iptables-legacy"
                      : "nftables")
               : "none");
}

fn netfilterer::setup_nat(std::string_view host_iface, std::string_view subnet)
    -> error_or<ok>
{
  if (!m_impl) return make_error("No firewall backend available");
  return m_impl->setup_nat(host_iface, subnet);
}

fn netfilterer::setup_forward(std::string_view host_iface) -> error_or<ok>
{
  if (!m_impl) return make_error("No firewall backend available");
  return m_impl->setup_forward(host_iface);
}

fn netfilterer::cleanup() -> error_or<ok>
{
  if (!m_impl) return ok{};
  return m_impl->cleanup();
}

} // namespace oo
