#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_util.hh"

#include <filesystem>
#include <optional>
#include <sched.h>
#include <string>

namespace oo {

class linux_namespace {
public:
  linux_namespace(std::string_view name) : m_name(name) {};
  ~linux_namespace();

  fn create_dir() -> error_or<ok>;
  fn is_dir_created() -> bool;
  fn unshare() -> error_or<ok>;
  fn get_path() -> error_or<std::filesystem::path>;
  fn get_name() -> const std::string &;

private:
  std::string m_name{};
  bool m_is_dir_created{false};
};

} // namespace oo
