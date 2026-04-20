#include "pid_tracker.hh"

#include "debug.hh"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace oo {

fn pid_tracker::is_alive(pid_t pid) -> bool
{
  trace_variables(verbosity::all, pid);
  if (pid <= 0) {
    return false;
  }

  std::filesystem::path proc_path = "/proc/" + std::to_string(pid);
  return std::filesystem::exists(proc_path);
}

fn pid_tracker::is_alive_and_matches(pid_t pid,
                                     std::string_view expected_cmdline) -> bool
{
  trace_variables(verbosity::all, pid, expected_cmdline);
  if (!is_alive(pid)) {
    return false;
  }

  std::filesystem::path cmdline_path =
      "/proc/" + std::to_string(pid) + "/cmdline";
  std::ifstream file(cmdline_path);
  if (!file.is_open()) {
    return false;
  }

  std::string cmdline;
  std::getline(file, cmdline, '\0'); // cmdline is null-separated

  return cmdline.find(expected_cmdline) != std::string::npos;
}

fn pid_tracker::read_pid_file(std::string_view path) -> error_or<pid_t>
{
  trace_variables(verbosity::all, path);
  std::ifstream file(path.data());
  if (!file.is_open()) {
    return make_error("Could not open PID file: " + std::string{path});
  }

  pid_t pid;
  file >> pid;

  if (file.fail()) {
    return make_error("Invalid PID in file: " + std::string{path});
  }

  return pid;
}

fn pid_tracker::write_pid_file(std::string_view path, pid_t pid) -> error_or<ok>
{
  trace_variables(verbosity::all, path, pid);
  std::filesystem::path file_path(path);
  std::filesystem::path parent = file_path.parent_path();

  if (!parent.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return make_error("Could not create directory for PID file: " +
                        ec.message());
    }
  }

  std::ofstream file(path.data());
  if (!file.is_open()) {
    return make_error("Could not open PID file for writing: " +
                      std::string{path});
  }

  file << pid << "\n";

  if (!file.good()) {
    return make_error("Error writing PID file");
  }

  trace(verbosity::debug, "Wrote PID {} to {}", pid, path);
  return ok{};
}

fn pid_tracker::remove_pid_file(std::string_view path) -> error_or<ok>
{
  trace_variables(verbosity::all, path);
  std::error_code ec;
  std::filesystem::remove(path.data(), ec);

  if (ec && ec != std::errc::no_such_file_or_directory) {
    return make_error("Could not remove PID file: " + ec.message());
  }

  trace(verbosity::debug, "Removed PID file {}", path);
  return ok{};
}

} // namespace oo
