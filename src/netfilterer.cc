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

netfilterer::netfilterer(linux_namespace &ns) : m_ns(ns)
{
  m_backend = detect_backend();
  trace(verbosity::info, "Using firewall backend: {}",
        m_backend == backend::iptables_legacy ? "iptables-legacy" : "nftables");
}

fn netfilterer::detect_backend() -> backend
{
  // SECURITY: Store the absolute path so all exec calls use it directly.
  // Never use a bare command name with execvp; a compromised PATH combined
  // with a setuid(0) child would allow arbitrary root code execution.
  if (std::filesystem::exists(constants::IPTABLES_LEGACY_SBIN_PATH)) {
    m_backend_path = std::string{constants::IPTABLES_LEGACY_SBIN_PATH};
    return backend::iptables_legacy;
  }
  if (std::filesystem::exists(constants::IPTABLES_LEGACY_BIN_PATH)) {
    m_backend_path = std::string{constants::IPTABLES_LEGACY_BIN_PATH};
    return backend::iptables_legacy;
  }
  if (std::filesystem::exists(constants::NFT_SBIN_PATH)) {
    m_backend_path = std::string{constants::NFT_SBIN_PATH};
    return backend::nftables;
  }
  if (std::filesystem::exists(constants::NFT_BIN_PATH)) {
    m_backend_path = std::string{constants::NFT_BIN_PATH};
    return backend::nftables;
  }
  return backend::unknown;
}

fn netfilterer::exec_iptables(const std::vector<std::string> &args)
    -> error_or<ok>
{
  pid_t pid = unwrap(oo_linux_syscall(fork));

  if (pid == 0) {
    let su = oo_linux_syscall(setuid, (uid_t) 0);
    if (su.is_err()) {
      trace(verbosity::error, "setuid(0) failed: {}",
            su.get_error().get_reason());
      exit(1);
    }
    trace(verbosity::debug, "setuid(0) ok, executing {}", m_backend_path);

    // SECURITY: Drop all inherited capabilities before exec. uid=0 is
    // sufficient for iptables to open /run/xtables.lock and run its root
    // check. No caps should propagate into the iptables process.
    unused(caps::drop_for_exec());

    std::vector<const char *> exec_args;
    exec_args.push_back(m_backend_path.c_str());
    for (const auto &arg : args) {
      exec_args.push_back(arg.c_str());
    }
    exec_args.push_back(nullptr);

    // SECURITY: Use absolute path (m_backend_path) detected at construction
    // time, never a bare command name, to prevent PATH-hijacking of this
    // setuid(0) child process.
    insist(!m_backend_path.empty(),
           "exec_iptables would run a bare command without backend path");
    execvp(m_backend_path.c_str(), const_cast<char *const *>(exec_args.data()));
    exit(1);
  }

  int status;
  unwrap(oo_linux_syscall(waitpid, pid, &status, 0));

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return make_error(m_backend_path + " command failed");
  }

  return ok{};
}

fn netfilterer::exec_nft(const std::vector<std::string> &args) -> error_or<ok>
{
  pid_t pid = unwrap(oo_linux_syscall(fork));

  if (pid == 0) {
    let su = oo_linux_syscall(setuid, (uid_t) 0);
    if (su.is_err()) {
      trace(verbosity::error, "setuid(0) failed: {}",
            su.get_error().get_reason());
      exit(1);
    }
    trace(verbosity::debug, "setuid(0) ok, executing {}", m_backend_path);

    // SECURITY: Drop all inherited capabilities before exec. uid=0 is
    // sufficient for nftables. No caps should propagate into the nft process.
    unused(caps::drop_for_exec());

    std::vector<const char *> exec_args;
    exec_args.push_back(m_backend_path.c_str());
    for (const auto &arg : args) {
      exec_args.push_back(arg.c_str());
    }
    exec_args.push_back(nullptr);

    // SECURITY: Absolute path prevents PATH-hijacking of setuid(0) child.
    insist(!m_backend_path.empty(),
           "exec_nft would run a bare command without backend path");
    execvp(m_backend_path.c_str(), const_cast<char *const *>(exec_args.data()));
    exit(1);
  }

  int status;
  unwrap(oo_linux_syscall(waitpid, pid, &status, 0));

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return make_error(m_backend_path + " command failed");
  }

  return ok{};
}

fn netfilterer::setup_nat(std::string_view host_iface, std::string_view subnet)
    -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface, subnet);
  if (m_backend == backend::iptables_legacy) {
    std::string subnet_str{subnet};
    std::string iface_str{host_iface};

    unwrap(exec_iptables({"-t", "nat", "-A", "POSTROUTING", "-s", subnet_str,
                          "-o", iface_str, "-j", "MASQUERADE"}));

    m_cleanup_cmds.push_back(m_backend_path + " -t nat -D POSTROUTING -s " +
                             subnet_str + " -o " + iface_str +
                             " -j MASQUERADE");

    trace(verbosity::info, "Setup NAT for {} via {}", subnet, host_iface);
  } else if (m_backend == backend::nftables) {
    std::string subnet_str{subnet};
    std::string iface_str{host_iface};

    unwrap(exec_nft({"add", "rule", "ip", "nat", "postrouting", "oifname",
                     iface_str, "ip", "saddr", subnet_str, "masquerade"}));

    // Nftables requires rule handles for precise deletion.
    trace(verbosity::info, "Setup NAT for {} via {} (nftables)", subnet,
          host_iface);
  } else {
    return make_error("No firewall backend available");
  }

  return ok{};
}

fn netfilterer::setup_forward(std::string_view host_iface) -> error_or<ok>
{
  trace_variables(verbosity::all, host_iface);
  if (m_backend == backend::iptables_legacy) {
    std::string iface_str{host_iface};

    unwrap(exec_iptables({"-A", "FORWARD", "-i", iface_str, "-j", "ACCEPT"}));

    m_cleanup_cmds.push_back(m_backend_path + " -D FORWARD -i " + iface_str +
                             " -j ACCEPT");

    unwrap(exec_iptables({"-A", "FORWARD", "-o", iface_str, "-j", "ACCEPT"}));

    m_cleanup_cmds.push_back(m_backend_path + " -D FORWARD -o " + iface_str +
                             " -j ACCEPT");

    trace(verbosity::info, "Setup FORWARD rules for {}", host_iface);
  } else if (m_backend == backend::nftables) {
    std::string iface_str{host_iface};

    unwrap(exec_nft({"add", "rule", "ip", "filter", "forward", "iifname",
                     iface_str, "accept"}));

    unwrap(exec_nft({"add", "rule", "ip", "filter", "forward", "oifname",
                     iface_str, "accept"}));

    trace(verbosity::info, "Setup FORWARD rules for {} (nftables)", host_iface);
  } else {
    return make_error("No firewall backend available");
  }

  return ok{};
}

fn netfilterer::cleanup() -> error_or<ok>
{
  if (m_cleaned_up) {
    return ok{};
  }

  if (m_backend == backend::iptables_legacy) {
    // SECURITY: cleanup_cmds are built only by setup_nat() and setup_forward()
    // from internal state. Whitespace splitting is safe because no
    // user-controlled data ever reaches m_cleanup_cmds. args[0] is always the
    // absolute backend path set by detect_backend(), not a PATH-searched name.
    for (const auto &cmd : m_cleanup_cmds) {
      std::vector<std::string> args;
      std::istringstream iss(cmd);
      std::string token;

      while (iss >> token) {
        args.push_back(token);
      }

      if (args.empty()) {
        continue;
      }

      let fork_result = oo_linux_syscall(fork);
      if (fork_result.is_err()) {
        continue;
      }
      pid_t pid = fork_result.get_value();

      if (pid == 0) {
        let su = oo_linux_syscall(setuid, (uid_t) 0);
        if (su.is_err()) {
          trace(verbosity::error, "setuid(0) failed: {}",
                su.get_error().get_reason());
          exit(1);
        }

        // SECURITY: Drop all inherited capabilities before exec.
        // uid=0 is sufficient for iptables cleanup; no caps needed.
        unused(caps::drop_for_exec());

        std::vector<const char *> exec_args;
        for (const auto &arg : args) {
          exec_args.push_back(arg.c_str());
        }
        exec_args.push_back(nullptr);

        insist(!args.empty() && !args[0].empty(),
               "cleanup command must supply a program path");
        execvp(args[0].c_str(), const_cast<char *const *>(exec_args.data()));
        exit(1);
      } else {
        int status;
        let wait_result = oo_linux_syscall(waitpid, pid, &status, 0);
        if (wait_result.is_err()) {
          trace(verbosity::error, "waitpid failed: {}",
                wait_result.get_error().get_reason());
          continue;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
          trace(verbosity::error, "Cleanup command failed: {}", cmd);
        }
      }
    }
    trace(verbosity::debug, "Cleaned up iptables rules");
  }

  m_cleanup_cmds.clear();
  m_cleaned_up = true;

  return ok{};
}

} // namespace oo
