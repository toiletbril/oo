#include "pid_tracker.hh"

#include "debug.hh"
#include "linux_util.hh"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace oo {

// /proc/<pid>/stat fields are whitespace-separated but field 2 (comm) is
// wrapped in parens and may contain whitespace or more parens. Skip past the
// last ')' and then scan whitespace-separated fields from there; field 22
// (start_time) is the 20th field after that point.
static fn parse_start_time(const std::string &content) -> error_or<u64> {
  let rparen = content.rfind(')');
  if (rparen == std::string::npos) {
    return make_error("malformed /proc/<pid>/stat: no ')'");
  }
  std::istringstream iss(content.substr(rparen + 1));
  std::string field;
  for (int i = 0; i < 20; ++i) {
    if (!(iss >> field)) {
      return make_error("/proc/<pid>/stat has fewer than 22 fields");
    }
  }
  char *end = nullptr;
  errno = 0;
  unsigned long long v = std::strtoull(field.c_str(), &end, 10);
  if (end == field.c_str() || *end != '\0' || errno != 0) {
    return make_error("non-numeric start_time in /proc/<pid>/stat: " + field);
  }
  return static_cast<u64>(v);
}

fn pid_tracker::read_start_time(pid_t pid) -> error_or<u64> {
  trace_variables(verbosity::all, pid);
  if (pid <= 0) {
    return make_error("read_start_time requires a positive pid");
  }
  std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
  if (!file.is_open()) {
    return make_error("could not open /proc/" + std::to_string(pid) + "/stat");
  }
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  return parse_start_time(content);
}

fn pid_tracker::is_alive_with_start_time(pid_t pid, u64 expected_start_time)
    -> bool {
  trace_variables(verbosity::all, pid, expected_start_time);
  if (pid <= 0)
    return false;
  let actual = read_start_time(pid);
  if (actual.is_err())
    return false;
  return actual.get_value() == expected_start_time;
}

fn pid_tracker::is_alive_and_matches(pid_t pid,
                                     std::string_view expected_cmdline)
    -> bool {
  trace_variables(verbosity::all, pid, expected_cmdline);
  if (pid <= 0)
    return false;

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

fn pid_tracker::read_pid_file(std::string_view path) -> error_or<pid_t> {
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

fn pid_tracker::write_pid_file(std::string_view path, pid_t pid)
    -> error_or<ok> {
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

fn pid_tracker::remove_pid_file(std::string_view path) -> error_or<ok> {
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
