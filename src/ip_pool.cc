#include "ip_pool.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <cassert>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace oo {

fn subnet::host_ip() const -> std::string {
  return "10.0." + std::to_string(third_octet) + ".1";
}

fn subnet::ns_ip() const -> std::string {
  return "10.0." + std::to_string(third_octet) + ".2";
}

fn subnet::to_string() const -> std::string {
  return "10.0." + std::to_string(third_octet) + ".0/30";
}

fn ip_pool::acquire_lock() -> error_or<ok> {
  m_lock_fd = ::open(LOCK_FILE, O_CREAT | O_RDWR, 0600);
  if (m_lock_fd < 0) {
    return make_error("Could not open lock file: " + std::string{LOCK_FILE} +
                      ": " + linux::get_errno_string());
  }
  struct flock fl{};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;
  if (::fcntl(m_lock_fd, F_SETLKW, &fl) != 0) {
    ::close(m_lock_fd);
    m_lock_fd = -1;
    return make_error("Could not acquire lock on: " + std::string{LOCK_FILE} +
                      ": " + linux::get_errno_string());
  }
  trace(verbosity::debug, "Acquired IP pool lock");
  return ok{};
}

fn ip_pool::release_lock() -> void {
  if (m_lock_fd >= 0) {
    ::close(m_lock_fd);
    m_lock_fd = -1;
    trace(verbosity::debug, "Released IP pool lock");
  }
}

ip_pool::ip_pool() {
  let lock_result = acquire_lock();
  if (lock_result.is_err()) {
    // SECURITY: If locking fails (e.g. /var/run/oo not yet created),
    // concurrent processes may race on ip-pool.ini. Log the failure.
    trace(verbosity::error, "Failed to acquire IP pool lock: {}",
          lock_result.get_error().get_reason());
  }
  let result = load();
  if (result.is_err()) {
    trace(verbosity::debug, "No existing pool file, starting fresh");
  }
}

ip_pool::~ip_pool() {
  let result = save();
  if (result.is_err()) {
    trace(verbosity::error, "Failed to save IP pool: {}",
          result.get_error().get_reason());
  }
  release_lock();
}

fn ip_pool::allocate() -> error_or<subnet> {
  for (usize i = 0; i < POOL_SIZE; ++i) {
    if (!m_allocated[i]) {
      m_allocated[i] = true;
      // SECURITY: i is bounded by the loop condition; assert guards against
      // future refactors that could pass an out-of-range index to subnet{}.
      assert(i < POOL_SIZE);
      subnet s{static_cast<u8>(i)};
      trace(verbosity::info, "Allocated subnet: {}", s.to_string());
      return s;
    }
  }
  return make_error("No available subnets in pool");
}

fn ip_pool::free(subnet s) -> error_or<ok> {
  trace_variables(verbosity::all, s.third_octet);
  if (!m_allocated[s.third_octet]) {
    return make_error("Subnet " + s.to_string() + " was not allocated");
  }
  m_allocated[s.third_octet] = false;
  trace(verbosity::info, "Freed subnet: {}", s.to_string());
  return ok{};
}

fn ip_pool::is_allocated(subnet s) const -> bool {
  trace_variables(verbosity::all, s.third_octet);
  return m_allocated[s.third_octet];
}

fn ip_pool::load() -> error_or<ok> {
  std::ifstream file(POOL_FILE);
  if (!file.is_open()) {
    return make_error("Could not open pool file: " + std::string{POOL_FILE} +
                      ": " + linux::get_errno_string());
  }

  m_allocated.fill(false);
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    std::istringstream iss(line);
    std::string key;
    char eq;
    int value;

    if (iss >> key >> eq >> value && eq == '=' && value == 1) {
      char *endptr = nullptr;
      unsigned long octet = strtoul(key.c_str(), &endptr, 10);
      if (endptr != key.c_str() && *endptr == '\0' && octet < POOL_SIZE) {
        m_allocated[octet] = true;
      } else {
        trace(verbosity::error, "Invalid pool entry: {}", line);
      }
    }
  }

  m_loaded = true;
  trace(verbosity::debug, "Loaded IP pool from {}", POOL_FILE);
  return ok{};
}

fn ip_pool::save() -> error_or<ok> {
  std::filesystem::path pool_path(POOL_FILE);
  std::filesystem::path pool_dir = pool_path.parent_path();

  std::error_code ec;
  std::filesystem::create_directories(pool_dir, ec);
  if (ec) {
    return make_error("Could not create pool directory: " + ec.message());
  }

  std::ofstream file(POOL_FILE);
  if (!file.is_open()) {
    return make_error(
        "Could not open pool file for writing: " + std::string{POOL_FILE} +
        ": " + linux::get_errno_string());
  }

  file << "# IP Pool allocation state\n";
  file << "# Format: <third_octet>=<1=allocated,0=free>\n";

  for (usize i = 0; i < POOL_SIZE; ++i) {
    if (m_allocated[i]) {
      file << i << "=1\n";
    }
  }

  if (!file.good()) {
    return make_error("Error writing to pool file: " + std::string{POOL_FILE} +
                      ": " + linux::get_errno_string());
  }

  trace(verbosity::debug, "Saved IP pool to {}", POOL_FILE);
  return ok{};
}

} // namespace oo
