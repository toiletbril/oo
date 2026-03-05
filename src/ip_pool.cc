#include "ip_pool.hh"
#include "debug.hh"

#include <fstream>
#include <sstream>

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

ip_pool::ip_pool() {
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
}

fn ip_pool::allocate() -> error_or<subnet> {
  for (usize i = 0; i < POOL_SIZE; ++i) {
    if (!m_allocated[i]) {
      m_allocated[i] = true;
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
    return make_error("Could not open pool file: " + std::string{POOL_FILE});
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
    return make_error("Could not open pool file for writing: " +
                      std::string{POOL_FILE});
  }

  file << "# IP Pool allocation state\n";
  file << "# Format: <third_octet>=<1=allocated,0=free>\n";

  for (usize i = 0; i < POOL_SIZE; ++i) {
    if (m_allocated[i]) {
      file << i << "=1\n";
    }
  }

  if (!file.good()) {
    return make_error("Error writing to pool file");
  }

  trace(verbosity::debug, "Saved IP pool to {}", POOL_FILE);
  return ok{};
}

} // namespace oo
