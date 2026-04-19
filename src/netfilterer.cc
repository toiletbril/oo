#include "netfilterer.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <filesystem>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

namespace oo {

netfilterer::netfilterer(linux_namespace &ns) : m_ns(ns) {
  m_backend = detect_backend();
  trace(verbosity::info, "Using firewall backend: {}",
        m_backend == backend::iptables_legacy ? "iptables-legacy" : "nftables");
}

fn netfilterer::detect_backend() -> backend {
  // Prioritize iptables-legacy if available.
  if (std::filesystem::exists(constants::IPTABLES_LEGACY_SBIN_PATH) ||
      std::filesystem::exists(constants::IPTABLES_LEGACY_BIN_PATH)) {
    return backend::iptables_legacy;
  }

  if (std::filesystem::exists(constants::NFT_SBIN_PATH) ||
      std::filesystem::exists(constants::NFT_BIN_PATH)) {
    return backend::nftables;
  }

  return backend::unknown;
}

fn netfilterer::exec_iptables(const std::vector<std::string> &args)
    -> error_or<ok> {
  pid_t pid = unwrap(oo_linux_syscall(fork));

  if (pid == 0) {
    let su = oo_linux_syscall(setuid, (uid_t)0);
    if (su.is_err()) {
      trace(verbosity::error, "setuid(0) failed: {}",
            su.get_error().get_reason());
      exit(1);
    }
    trace(verbosity::debug, "setuid(0) ok, executing {}",
          constants::IPTABLES_LEGACY_CMD);

    std::vector<const char *> exec_args;
    exec_args.push_back(constants::IPTABLES_LEGACY_CMD.data());
    for (const auto &arg : args) {
      exec_args.push_back(arg.c_str());
    }
    exec_args.push_back(nullptr);

    execvp(constants::IPTABLES_LEGACY_CMD.data(),
           const_cast<char *const *>(exec_args.data()));
    exit(1);
  }

  int status;
  unwrap(oo_linux_syscall(waitpid, pid, &status, 0));

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return make_error(std::string{constants::IPTABLES_LEGACY_CMD} +
                      " command failed");
  }

  return ok{};
}

fn netfilterer::exec_nft(const std::vector<std::string> &args) -> error_or<ok> {
  pid_t pid = unwrap(oo_linux_syscall(fork));

  if (pid == 0) {
    let su = oo_linux_syscall(setuid, (uid_t)0);
    if (su.is_err()) {
      trace(verbosity::error, "setuid(0) failed: {}",
            su.get_error().get_reason());
      exit(1);
    }
    trace(verbosity::debug, "setuid(0) ok, executing {}", constants::NFT_CMD);

    std::vector<const char *> exec_args;
    exec_args.push_back(constants::NFT_CMD.data());
    for (const auto &arg : args) {
      exec_args.push_back(arg.c_str());
    }
    exec_args.push_back(nullptr);

    execvp(constants::NFT_CMD.data(),
           const_cast<char *const *>(exec_args.data()));
    exit(1);
  }

  int status;
  unwrap(oo_linux_syscall(waitpid, pid, &status, 0));

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return make_error(std::string{constants::NFT_CMD} + " command failed");
  }

  return ok{};
}

fn netfilterer::setup_nat(std::string_view host_iface, std::string_view subnet)
    -> error_or<ok> {
  trace_variables(verbosity::all, host_iface, subnet);
  if (m_backend == backend::iptables_legacy) {
    std::string subnet_str{subnet};
    std::string iface_str{host_iface};

    unwrap(exec_iptables({"-t", "nat", "-A", "POSTROUTING", "-s", subnet_str,
                          "-o", iface_str, "-j", "MASQUERADE"}));

    m_cleanup_cmds.push_back(std::string{constants::IPTABLES_LEGACY_CMD} +
                             " -t nat -D POSTROUTING -s " + subnet_str +
                             " -o " + iface_str + " -j MASQUERADE");

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

fn netfilterer::setup_forward(std::string_view host_iface) -> error_or<ok> {
  trace_variables(verbosity::all, host_iface);
  if (m_backend == backend::iptables_legacy) {
    std::string iface_str{host_iface};

    unwrap(exec_iptables({"-A", "FORWARD", "-i", iface_str, "-j", "ACCEPT"}));

    m_cleanup_cmds.push_back(std::string{constants::IPTABLES_LEGACY_CMD} +
                             " -D FORWARD -i " + iface_str + " -j ACCEPT");

    unwrap(exec_iptables({"-A", "FORWARD", "-o", iface_str, "-j", "ACCEPT"}));

    m_cleanup_cmds.push_back(std::string{constants::IPTABLES_LEGACY_CMD} +
                             " -D FORWARD -o " + iface_str + " -j ACCEPT");

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

fn netfilterer::cleanup() -> error_or<ok> {
  if (m_cleaned_up) {
    return ok{};
  }
  m_cleaned_up = true;

  if (m_backend == backend::iptables_legacy) {
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
        let su = oo_linux_syscall(setuid, (uid_t)0);
        if (su.is_err()) {
          trace(verbosity::error, "setuid(0) failed: {}",
                su.get_error().get_reason());
          exit(1);
        }

        std::vector<const char *> exec_args;
        for (const auto &arg : args) {
          exec_args.push_back(arg.c_str());
        }
        exec_args.push_back(nullptr);

        execvp(args[0].c_str(), const_cast<char *const *>(exec_args.data()));
        exit(1);
      } else {
        int status;
        unwrap(oo_linux_syscall(waitpid, pid, &status, 0));
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
          trace(verbosity::error, "Cleanup command failed: {}", cmd);
        }
      }
    }
    trace(verbosity::debug, "Cleaned up iptables rules");
  }

  m_cleanup_cmds.clear();

  return ok{};
}

} // namespace oo
