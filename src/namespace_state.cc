#include "namespace_state.hh"
#include "debug.hh"

#include <fstream>
#include <sstream>

namespace oo {

fn namespace_state::load(linux_namespace &ns) -> error_or<namespace_state> {
  let ns_path = unwrap(ns.get_path());
  let state_path = ns_path / STATE_FILE;

  std::ifstream file(state_path);
  if (!file.is_open()) {
    return make_error("Could not open state file: " + state_path.string());
  }

  namespace_state state;
  std::string line;

  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    let eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    std::string key = line.substr(0, eq_pos);
    std::string value = line.substr(eq_pos + 1);

    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);

    if (key == "daemon_pid") {
      state.daemon_pid = std::stoi(value);
    } else if (key == "child_pid") {
      state.child_pid = std::stoi(value);
    } else if (key == "subnet_octet") {
      state.subnet_octet = static_cast<u8>(std::stoul(value));
    } else if (key == "veth_host") {
      state.veth_host = value;
    } else if (key == "veth_ns") {
      state.veth_ns = value;
    }
  }

  trace(verbosity::debug, "Loaded namespace state from {}",
        state_path.string());
  return state;
}

fn namespace_state::save(linux_namespace &ns) const -> error_or<ok> {
  let ns_path = unwrap(ns.get_path());
  let state_path = ns_path / STATE_FILE;

  std::ofstream file(state_path);
  if (!file.is_open()) {
    return make_error("Could not open state file for writing: " +
                      state_path.string());
  }

  file << "# Namespace runtime state\n";
  file << "daemon_pid=" << daemon_pid << "\n";
  file << "child_pid=" << child_pid << "\n";
  file << "subnet_octet=" << static_cast<u32>(subnet_octet) << "\n";
  file << "veth_host=" << veth_host << "\n";
  file << "veth_ns=" << veth_ns << "\n";

  if (!file.good()) {
    return make_error("Error writing to state file");
  }

  trace(verbosity::debug, "Saved namespace state to {}", state_path.string());
  return ok{};
}

} // namespace oo
