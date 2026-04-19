#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_util.hh"

#include <filesystem>
#include <optional>
#include <sched.h>
#include <string>

namespace oo {

class network_configurator;

class linux_namespace {
public:
  linux_namespace(std::string_view name) : m_name(name) {};
  ~linux_namespace();

  fn create_dir() -> error_or<ok>;
  fn is_dir_created() -> bool;
  fn unshare() -> error_or<ok>;
  fn get_path() -> error_or<std::filesystem::path>;
  fn get_name() -> const std::string &;
  fn reset(network_configurator &ns) -> error_or<ok>;

private:
  // SECURITY: MAX_NS_NAME_LEN enforces the IFNAMSIZ limit on veth interface
  // names. The generated name is "veth-<name>-host" = 10 + len chars, and
  // IFNAMSIZ=16 (including null terminator) leaves 5 chars for the name.
  // Relaxing this silently truncates interface names in the kernel.
  static constexpr usize MAX_NS_NAME_LEN = 5;

  std::string m_name{};
  bool m_is_dir_created{false};
};

} // namespace oo
