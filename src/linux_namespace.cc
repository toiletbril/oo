#include "linux_namespace.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"
#include "network_configurator.hh"

#include <cassert>
#include <cctype>
#include <unistd.h>

namespace oo {

linux_namespace::~linux_namespace() = default;

// SECURITY: The namespace name is used as a filesystem path component AND as
// part of veth interface names ("veth-<name>-host", "veth-<name>-ns").
// Validation is load-bearing. Do not relax without understanding:
//   1. IFNAMSIZ limit (MAX_NS_NAME_LEN = 5)
//   2. Path traversal via '..' or special chars in the name
fn linux_namespace::validate_name() -> error_or<ok> {
  if (m_name.empty()) {
    return make_error("Namespace name must not be empty.");
  }

  if (m_name.find('/') != std::string::npos) {
    return make_error("Namespace name must not include a slash. (" + m_name +
                      ")");
  }

  if (m_name.size() > MAX_NS_NAME_LEN) {
    return make_error(
        "Namespace name too long (max " + std::to_string(MAX_NS_NAME_LEN) +
        " chars); veth interface names would exceed IFNAMSIZ. (" + m_name +
        ")");
  }

  // SECURITY: Restrict to [a-zA-Z0-9_-] to prevent path traversal via '..'
  // and unexpected behavior in interface name or filename contexts.
  for (char c : m_name) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      return make_error(
          std::string{"Namespace name contains invalid character '"} + c +
          "'. Only alphanumeric, '-', and '_' are allowed. (" + m_name + ")");
    }
  }

  assert(m_name.size() <= MAX_NS_NAME_LEN);
  return ok{};
}

fn linux_namespace::create_dir() -> error_or<ok> {
  if (is_dir_created()) {
    trace(verbosity::debug, "Directory already created for namespace '{}'",
          m_name);
    return ok{};
  }

  unwrap(validate_name());

  std::error_code ec;
  let path = unwrap(get_path());

  trace(verbosity::info, "Creating namespace directory: {}", path.string());
  std::filesystem::create_directories(path, ec);

  if (ec) {
    return make_error("Could not create '" + path.string() +
                      "': " + ec.message());
  }

  // Set ownership to current user so non-root users own their namespaces.
  unwrap(oo_linux_syscall(chown, path.c_str(), getuid(), getgid()));

  // Set restrictive permissions so only the creator can access.
  std::error_code perm_ec;
  std::filesystem::permissions(path, std::filesystem::perms::owner_all,
                               perm_ec);
  unwrap(
      oo_error_code(perm_ec, "Failed to set permissions on " + path.string()));

  m_is_dir_created = true;
  trace(verbosity::debug, "Namespace directory created successfully");

  return ok{};
}

fn linux_namespace::unshare() -> error_or<ok> {
  trace(verbosity::info, "Unsharing network namespace");
  let result = oo_linux_syscall(::unshare, CLONE_NEWNET);
  if (result.is_err()) {
    return result.get_error();
  }
  trace(verbosity::debug, "Network namespace unshared successfully");
  return ok{};
}

fn linux_namespace::get_path() -> error_or<std::filesystem::path> {
  return std::filesystem::path{constants::OO_RUN_DIR}.append(m_name);
}

fn linux_namespace::is_dir_created() -> bool { return m_is_dir_created; }

fn linux_namespace::get_name() -> const std::string & { return m_name; }

fn linux_namespace::reset(network_configurator &nc) -> error_or<ok> {
  unused(nc.cleanup());

  let ns_path_result = get_path();
  if (!ns_path_result.is_err()) {
    std::error_code ec;
    std::filesystem::remove_all(ns_path_result.get_value(), ec);
    if (ec) {
      trace(verbosity::error, "Failed to remove namespace directory: {}",
            ec.message());
    } else {
      trace(verbosity::debug, "Removed namespace directory: {}",
            ns_path_result.get_value().string());
    }
  }

  return ok{};
}

} // namespace oo
