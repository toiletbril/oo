#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"

#include <string>
#include <vector>

namespace oo {

// Manages firewall rules using iptables-legacy or nftables
// Priority: iptables-legacy first, then nftables fallback
class netfilterer {
public:
  netfilterer(linux_namespace &ns);
  ~netfilterer() = default;

  // Setup NAT and forwarding rules for interface
  fn setup_nat(std::string_view host_iface, std::string_view subnet)
      -> error_or<ok>;

  // Setup forwarding rules
  fn setup_forward(std::string_view host_iface) -> error_or<ok>;

  // Remove all tracked rules
  fn cleanup() -> error_or<ok>;

private:
  enum class backend { iptables_legacy, nftables, unknown };

  linux_namespace &m_ns;
  backend m_backend{backend::unknown};
  // Absolute path to the firewall binary detected at construction time.
  // SECURITY: Always use this for execvp, never a bare command name, to prevent
  // PATH-based hijacking of the setuid(0) child process.
  std::string m_backend_path{};
  bool m_cleaned_up{false};
  std::vector<std::string> m_cleanup_cmds;

  fn detect_backend() -> backend;
  fn exec_iptables(const std::vector<std::string> &args) -> error_or<ok>;
  fn exec_nft(const std::vector<std::string> &args) -> error_or<ok>;
};

} // namespace oo
