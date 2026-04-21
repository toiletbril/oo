#pragma once

#include "common.hh"
#include "constants.hh"
#include "error.hh"
#include "ini.hh"
#include "lock.hh"

#include <string>

namespace oo {

class linux_namespace;

// A subnet within 10.0.X.0/<prefix_len> where X is the third octet. The pool
// allocates by third octet (always /30-keyed internally); the prefix is
// chosen per `oo up` invocation and controls the actual netmask on the veth
// interface. Wider prefixes can overlap across namespaces; that is the
// user's responsibility.
class subnet
{
public:
  subnet() = default;
  explicit subnet(u8 third_octet) : m_third_octet(third_octet) {}
  subnet(u8 third_octet, u8 prefix_len)
      : m_third_octet(third_octet), m_prefix_len(prefix_len)
  {}

  [[nodiscard]] fn host_ip() const -> std::string;
  [[nodiscard]] fn ns_ip() const -> std::string;
  [[nodiscard]] fn to_string() const -> std::string;

  [[nodiscard]] fn get_third_octet() const -> u8 { return m_third_octet; }
  [[nodiscard]] fn get_prefix_len() const -> u8 { return m_prefix_len; }

private:
  u8 m_third_octet{0};
  u8 m_prefix_len{constants::DEFAULT_SUBNET_PREFIX_LEN};
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
