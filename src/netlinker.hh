#pragma once

#include "common.hh"
#include "error.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "netlink_socket.hh"

#include <memory>
#include <string>

namespace oo {

// Raw netlink socket wrapper for network operations
// Uses rtnetlink protocol for link/addr/route manipulation
class netlinker {
public:
  netlinker(linux_namespace &ns);
  ~netlinker();

  // Create veth pair (host side and namespace side)
  fn create_veth_pair(std::string_view host_name, std::string_view ns_name)
      -> error_or<ok>;

  // Move interface to namespace by PID
  fn move_to_namespace(std::string_view ifname, pid_t target_pid)
      -> error_or<ok>;

  // Add IP address to interface
  fn add_address(std::string_view ifname, std::string_view ip, u8 prefix_len)
      -> error_or<ok>;

  // Add route
  fn add_route(std::string_view dest_ip, u8 prefix_len,
               std::string_view gateway) -> error_or<ok>;

  // Set link up
  fn set_link_up(std::string_view ifname) -> error_or<ok>;

  // Set link down
  fn set_link_down(std::string_view ifname) -> error_or<ok>;

  // Delete link
  fn delete_link(std::string_view ifname) -> error_or<ok>;

private:
  linux_namespace &m_ns;
  std::unique_ptr<netlink_socket> m_sock;

  // Get interface index by name
  fn get_ifindex(std::string_view ifname) -> error_or<u32>;
};

} // namespace oo
