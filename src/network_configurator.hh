#pragma once

#include "common.hh"
#include "error.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "netfilterer.hh"
#include "netlinker.hh"

#include <string>

namespace oo {

// Orchestrates network setup: veth pair, IPs, routes, firewall.
// Detects default route interface automatically.
class network_configurator
{
public:
  network_configurator(linux_namespace &ns, subnet s);
  ~network_configurator();

  // Setup complete network stack.
  fn initial_setup() -> error_or<ok>;
  fn finish_setup(pid_t daemon_pid) -> error_or<ok>;

  // Cleanup network resources.
  fn cleanup() -> error_or<ok>;

  fn save() const -> error_or<ok>;
  fn load() -> error_or<ok>;

  fn get_veth_host_name() const -> std::string_view
  {
    return m_netlinker.get_veth_host_name();
  }
  fn get_veth_ns_name() const -> std::string_view
  {
    return m_netlinker.get_veth_ns_name();
  }
  fn get_subnet_octet() const -> u8 { return m_subnet.third_octet; }
  fn get_netlinker() -> netlinker & { return m_netlinker; }

private:
  linux_namespace &m_ns;
  subnet m_subnet;
  netlinker m_netlinker;
  netfilterer m_netfilterer;
  std::string m_default_iface;

  bool m_setup_done{false};
  bool m_initial_setup_done{false};

  fn detect_default_interface() -> error_or<std::string>;
  fn enable_ip_forward() -> error_or<ok>;

  static constexpr const char *NET_FILE = "network.ini";
};

} // namespace oo
