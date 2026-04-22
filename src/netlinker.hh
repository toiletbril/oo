#pragma once

#include "common.hh"
#include "error.hh"
#include "ip_pool.hh"
#include "linux_namespace.hh"
#include "netlink_socket.hh"

#include <string>

namespace oo {

// Raw netlink socket wrapper for network operations
// Uses rtnetlink protocol for link/addr/route manipulation
class netlinker {
public:
  netlinker(linux_namespace &ns);
  ~netlinker();

  [[nodiscard]] fn create_veth_pair(std::string_view host_name,
                                    std::string_view ns_name) -> error_or<ok>;
  [[nodiscard]] fn move_to_namespace(std::string_view ifname, pid_t target_pid)
      -> error_or<ok>;
  [[nodiscard]] fn add_address(std::string_view ifname, std::string_view ip,
                               u8 prefix_len) -> error_or<ok>;
  [[nodiscard]] fn add_route(std::string_view dest_ip, u8 prefix_len,
                             std::string_view gateway) -> error_or<ok>;
  [[nodiscard]] fn set_link_up(std::string_view ifname) -> error_or<ok>;

  [[nodiscard]] fn set_link_down(std::string_view ifname) -> error_or<ok>;
  [[nodiscard]] fn delete_link(std::string_view ifname) -> error_or<ok>;
  [[nodiscard]] fn cleanup() -> error_or<ok>;

  [[nodiscard]] fn get_veth_host_name() const -> std::string_view {
    return m_veth_host;
  }
  [[nodiscard]] fn get_veth_ns_name() const -> std::string_view {
    return m_veth_ns;
  }
  fn set_veth_host_name(std::string_view name) -> void { m_veth_host = name; }

private:
  linux_namespace &m_ns;
  netlink_socket m_sock;
  std::string m_veth_host;
  std::string m_veth_ns;
  bool m_cleaned_up{false};

  // Get interface index by name
  fn get_ifindex(std::string_view ifname) -> error_or<u32>;
  fn generate_veth_names() -> void;
};

} // namespace oo
