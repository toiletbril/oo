#include "ip_pool.hh"

#include "debug.hh"
#include "linux_namespace.hh"

#include <array>
#include <cstdlib>
#include <filesystem>

namespace oo {

subnet::subnet(u8 third_octet, u8 prefix_len)
    : m_third_octet(third_octet), m_prefix_len(prefix_len)
{
  trace(verbosity::info, "Subnet {}", to_string());
}

fn subnet::host_ip() const -> std::string
{
  return "10.0." + std::to_string(m_third_octet) + ".1";
}

fn subnet::ns_ip() const -> std::string
{
  return "10.0." + std::to_string(m_third_octet) + ".2";
}

fn subnet::to_string() const -> std::string
{
  return "10.0." + std::to_string(m_third_octet) + ".0/" +
         std::to_string(static_cast<u32>(m_prefix_len));
}

// The pool key always uses /30 regardless of the chosen prefix so the
// bitmap remains third-octet keyed. Wider prefixes chosen by the user are
// stored per-namespace in network.ini, not in the pool.
static fn pool_key(u8 third_octet) -> std::string
{
  return "10.0." + std::to_string(third_octet) + ".0/30";
}

ip_pool::ip_pool(linux_namespace &ns)
    : m_ns(ns), m_lock(LOCK_FILE), m_file(POOL_FILE)
{
  std::error_code ec;
  let pool_dir = std::filesystem::path{POOL_FILE}.parent_path();
  if (!pool_dir.empty() && !std::filesystem::exists(pool_dir, ec)) {
    std::filesystem::create_directories(pool_dir, ec);
    if (ec) {
      trace(verbosity::error, "Failed to create pool directory {}: {}",
            pool_dir.string(), ec.message());
    }
  }

  if (let r = m_lock.acquire(); r.is_err()) {
    trace(verbosity::error, "Failed to acquire IP pool lock: {}",
          r.get_error().get_reason());
  }

  m_file.set_header(
      "IP Pool allocation state\nFormat: <subnet>=<namespace_name>");
}

static fn parse_octet_from_key(const std::string &key) -> error_or<u8>
{
  let first_dot = key.find('.');
  if (first_dot == std::string::npos) {
    return make_error("Invalid pool key: " + key);
  }
  let second_dot = key.find('.', first_dot + 1);
  if (second_dot == std::string::npos) {
    return make_error("Invalid pool key: " + key);
  }
  let third_dot = key.find('.', second_dot + 1);
  if (third_dot == std::string::npos) {
    return make_error("Invalid pool key: " + key);
  }

  let octet_str = key.substr(second_dot + 1, third_dot - second_dot - 1);
  char *end = nullptr;
  unsigned long v = strtoul(octet_str.c_str(), &end, 10);
  if (end == octet_str.c_str() || *end != '\0' || v >= 256) {
    return make_error("Invalid pool key: " + key);
  }

  return static_cast<u8>(v);
}

fn ip_pool::allocate() -> error_or<subnet>
{
  trace(verbosity::debug, "Allocating subnet for namespace '{}'",
        m_ns.get_name());
  if (!m_lock.is_held()) {
    return make_error("Cannot allocate: IP pool lock not held");
  }
  unwrap(m_file.load());

  std::array<bool, POOL_SIZE> taken{};
  for (const let &e : m_file.entries()) {
    let octet = unwrap(parse_octet_from_key(e.key));
    insist(static_cast<usize>(octet) < POOL_SIZE,
           "parsed octet escapes the pool bitmap bounds");
    taken[octet] = true;
  }

  for (usize i = 0; i < POOL_SIZE; ++i) {
    if (!taken[i]) {
      const subnet s{static_cast<u8>(i)};
      m_file.append(pool_key(s.get_third_octet()), m_ns.get_name());
      trace(verbosity::info, "Allocated subnet: {} -> {}", s.to_string(),
            m_ns.get_name());
      return s;
    }
  }

  return make_error("No available subnets in pool");
}

fn ip_pool::free(subnet s) -> error_or<ok>
{
  trace(verbosity::debug, "free({}/{})", s.get_third_octet(),
        s.get_prefix_len());
  if (!m_lock.is_held()) {
    return make_error("Cannot free: IP pool lock not held");
  }
  unwrap(m_file.load());

  const std::string key = pool_key(s.get_third_octet());
  let owner = m_file.find(key);
  if (!owner.has_value()) {
    return make_error("Subnet " + key + " was not allocated");
  }
  if (*owner != m_ns.get_name()) {
    return make_error("Subnet " + key + " is owned by '" + *owner + "', not '" +
                      m_ns.get_name() + "'");
  }

  insist(owner.has_value() && *owner == m_ns.get_name(),
         "remove runs only after ownership is confirmed");
  m_file.remove(key);
  trace(verbosity::info, "Freed subnet: {}", key);

  return ok{};
}

} // namespace oo
