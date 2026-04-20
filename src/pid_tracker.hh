#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/types.h>

namespace oo {

// Check PID liveness and handle stale PID detection
class pid_tracker
{
public:
  // Check if PID is alive via /proc/<pid>
  static fn is_alive(pid_t pid) -> bool;

  // Check if PID is alive and belongs to expected command
  static fn is_alive_and_matches(pid_t pid, std::string_view expected_cmdline)
      -> bool;

  // Read PID from file
  static fn read_pid_file(std::string_view path) -> error_or<pid_t>;

  // Write PID to file (atomic, creates parent dirs)
  static fn write_pid_file(std::string_view path, pid_t pid) -> error_or<ok>;

  // Remove PID file
  static fn remove_pid_file(std::string_view path) -> error_or<ok>;
};

} // namespace oo
