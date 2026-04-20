#pragma once

#include "common.hh"
#include "error.hh"
#include "ini.hh"
#include "lock.hh"

#include <string>

namespace oo {

class linux_namespace;

// A /30 subnet within 10.0.X.0/30 where X is the third_octet.
struct subnet
{
  u8 third_octet;

  fn host_ip() const -> std::string;
  fn ns_ip() const -> std::string;
  fn to_string() const -> std::string;
};

// Namespace-scoped handle over the shared IP pool file at
// /var/run/oo/ip-pool.ini. The lock is acquired on construction and held
// for the lifetime of the object; entries live in an ini_file member and
// are flushed on destruction.
class ip_pool
{
public:
  explicit ip_pool(linux_namespace &ns);
  ~ip_pool() = default;

  ip_pool(ip_pool &&other) noexcept = default;
  ip_pool(const ip_pool &) = delete;
  ip_pool &operator=(const ip_pool &) = delete;
  ip_pool &operator=(ip_pool &&) = delete;

  fn allocate() -> error_or<subnet>;
  fn free(subnet s) -> error_or<ok>;

private:
  static constexpr const char *POOL_FILE = "/var/run/oo/ip-pool.ini";
  // SECURITY: Lock file serializes concurrent oo processes that would
  // otherwise race on ip-pool.ini reads and writes, potentially allocating
  // the same subnet twice.
  static constexpr const char *LOCK_FILE = "/var/run/oo/ip-pool.lock";
  static constexpr usize POOL_SIZE = 256;

  linux_namespace &m_ns;
  file_lock m_lock;
  ini_file m_file;
};

} // namespace oo
