#include "netfilterer.hh"

#include "caps.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <filesystem>
#include <sstream>
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
    // setuid(0) above.
    unused(caps::drop_for_exec());

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

fn iptables_legacy_backend::setup_nat(std::string_view host_iface,
                                      std::string_view subnet) -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface, subnet);
  const std::string subnet_str{subnet};
  const std::string iface_str{host_iface};

  unwrap(run_privileged({m_backend_path, "-t", "nat", "-A", "POSTROUTING", "-s",
                         subnet_str, "-o", iface_str, "-j", "MASQUERADE"}));

  m_cleanup_cmds.push_back(m_backend_path + " -t nat -D POSTROUTING -s " +
                           subnet_str + " -o " + iface_str + " -j MASQUERADE");

  trace(verbosity::info, "Setup NAT for {} via {}", subnet, host_iface);

  return ok{};
}

fn iptables_legacy_backend::setup_forward(std::string_view host_iface)
    -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface);
  const std::string iface_str{host_iface};

  unwrap(run_privileged(
      {m_backend_path, "-A", "FORWARD", "-i", iface_str, "-j", "ACCEPT"}));
  m_cleanup_cmds.push_back(m_backend_path + " -D FORWARD -i " + iface_str +
                           " -j ACCEPT");

  unwrap(run_privileged(
      {m_backend_path, "-A", "FORWARD", "-o", iface_str, "-j", "ACCEPT"}));
  m_cleanup_cmds.push_back(m_backend_path + " -D FORWARD -o " + iface_str +
                           " -j ACCEPT");

  trace(verbosity::info, "Setup FORWARD rules for {}", host_iface);

  return ok{};
}

fn iptables_legacy_backend::cleanup() -> error_or<ok>
{
  if (m_cleaned_up) {
    return ok{};
  }

  // SECURITY: cleanup_cmds are built only by setup_nat and setup_forward
  // from internal state. Whitespace splitting is safe because no
  // user-controlled data ever reaches m_cleanup_cmds. args[0] is always
  // the absolute backend path set at construction time.
  for (const let &cmd : m_cleanup_cmds) {
    std::vector<std::string> args;
    std::istringstream iss(cmd);
    std::string token;

    while (iss >> token) {
      args.push_back(token);
    }

    if (args.empty()) {
      continue;
    }

    if (let r = run_privileged(args); r.is_err()) {
      trace(verbosity::error, "Cleanup command failed: {}", cmd);
    }
  }

  trace(verbosity::debug, "Cleaned up iptables rules");
  m_cleanup_cmds.clear();
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

  // Nftables tracking of rule handles is not implemented yet; leave rules
  // in place rather than risk flushing unrelated state.
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
