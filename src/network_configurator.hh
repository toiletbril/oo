#pragma once

#include "common.hh"
#include "error.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "netfilterer.hh"
#include "netlinker.hh"

#include <memory>
#include <string>

namespace oo {

// Orchestrates network setup: veth pair, IPs, routes, firewall.
// Detects default route interface automatically.
class network_configurator {
public:
  network_configurator(linux_namespace &ns, subnet s);
  ~network_configurator();

  // Setup complete network stack.
  fn initial_setup() -> error_or<ok>;
  fn finish_setup(pid_t daemon_pid) -> error_or<ok>;

  // Cleanup network resources.
  fn prepare_cleanup(std::string_view veth_host) -> void;
  fn cleanup() -> error_or<ok>;

private:
  linux_namespace &m_ns;
  subnet m_subnet;
  std::unique_ptr<netlinker> m_netlinker;
  std::unique_ptr<netfilterer> m_netfilterer;
  std::string m_veth_host;
  std::string m_veth_ns;
  std::string m_default_iface;

  bool m_setup_done{false};
  bool m_initial_setup_done{false};

  fn detect_default_interface() -> error_or<std::string>;
  fn enable_ip_forward() -> error_or<ok>;
  fn generate_veth_names() -> void;
};

} // namespace oo
