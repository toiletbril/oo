#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"

#include <string>
#include <vector>

namespace oo {

// Manages DNS configuration for namespace
// Generates resolv.conf and nsswitch.conf files
class dominatrix {
public:
  dominatrix(linux_namespace &ns);
  ~dominatrix() = default;

  dominatrix(const dominatrix &) = delete;
  dominatrix &operator=(const dominatrix &) = delete;

  // Parse DNS entries (either IPs or file path)
  [[nodiscard]] fn set_dns_servers(const std::vector<std::string> &dns_servers)
      -> error_or<ok>;
  [[nodiscard]] fn set_dns_file(std::string_view dns_file_path) -> error_or<ok>;

  // Generate and write DNS config files to namespace directory
  [[nodiscard]] fn write_configs() -> error_or<ok>;

  // Get paths to generated files
  [[nodiscard]] fn get_resolv_conf_path() -> error_or<std::string>;
  [[nodiscard]] fn get_nsswitch_conf_path() -> error_or<std::string>;

private:
  linux_namespace &m_ns;
  std::vector<std::string> m_dns_servers;
  std::string m_dns_file_path;
  linux::oo_fd m_dns_fd;

  fn is_ip_address(std::string_view s) -> bool;
};

} // namespace oo
