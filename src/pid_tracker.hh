#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/types.h>

namespace oo {

// Check PID liveness and handle stale PID detection
class pid_tracker
{
public:
  // Read field 22 (start time in jiffies) from /proc/<pid>/stat. Returns
  // error if the pid no longer exists or /proc/<pid>/stat cannot be parsed.
  static fn read_starttime(pid_t pid) -> error_or<u64>;

  // Check the process is alive AND was started at the recorded time. This
  // closes the PID-reuse window where another user's process inherits a
  // recycled pid number. Returns false on any parse failure.
  static fn is_alive_with_starttime(pid_t pid, u64 expected_starttime) -> bool;

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
