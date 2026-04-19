#pragma once

#include "common.hh"
#include "error.hh"

#include <array>
#include <filesystem>
#include <optional>

namespace oo {

// Manages allocation of 10.oo.X.0/30 subnets where X = 0-255
// Persists state to /var/run/oo/ip-pool.ini as ini file
struct subnet {
  u8 third_octet; // X in 10.oo.X.0/30

  fn host_ip() const -> std::string;
  fn ns_ip() const -> std::string;
  fn to_string() const -> std::string;
};

class ip_pool {
public:
  ip_pool();
  ~ip_pool();

  // Allocate next available subnet
  fn allocate() -> error_or<subnet>;

  // Free a specific subnet
  fn free(subnet s) -> error_or<ok>;

  // Check if subnet is allocated
  fn is_allocated(subnet s) const -> bool;

private:
  static constexpr const char *POOL_FILE = "/var/run/oo/ip-pool.ini";
  // SECURITY: Lock file serializes concurrent oo processes that would
  // otherwise race on ip-pool.ini reads and writes, potentially allocating
  // the same subnet twice. The fd is held open for the ip_pool lifetime
  // (constructor to destructor) and released on close(), which releases
  // all fcntl locks held by this process on the file.
  static constexpr const char *LOCK_FILE = "/var/run/oo/ip-pool.lock";
  static constexpr usize POOL_SIZE = 256;

  std::array<bool, POOL_SIZE> m_allocated{};
  bool m_loaded{false};
  int m_lock_fd{-1};

  fn acquire_lock() -> error_or<ok>;
  fn release_lock() -> void;
  fn load() -> error_or<ok>;
  fn save() -> error_or<ok>;
};

} // namespace oo
