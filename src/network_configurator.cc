#include "network_configurator.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <fcntl.h>
#include <fstream>
#include <sched.h>
#include <sstream>

namespace oo {

network_configurator::network_configurator(linux_namespace &ns, subnet s)
    : m_ns(ns), m_subnet(s), m_netlinker(ns), m_netfilterer(ns) {}

network_configurator::~network_configurator() = default;

fn network_configurator::detect_default_interface() -> error_or<std::string> {
  std::ifstream route_file(constants::PROC_NET_ROUTE);
  if (!route_file.is_open()) {
    return make_error("Could not open " +
                      std::string{constants::PROC_NET_ROUTE} + ": " +
                      linux::get_errno_string());
  }

  std::string line;
  std::getline(route_file, line);

  while (std::getline(route_file, line)) {
    std::istringstream iss(line);
    std::string iface, dest, gateway;

    if (!(iss >> iface >> dest >> gateway)) {
      continue;
    }

    if (dest == constants::DEFAULT_ROUTE_DEST) {
      trace(verbosity::info, "Detected default interface: {}", iface);
      return iface;
    }
  }

  return make_error("No default route found in " +
                    std::string{constants::PROC_NET_ROUTE});
}

fn network_configurator::enable_ip_forward() -> error_or<ok> {
  std::ifstream check_file(std::string{constants::PROC_IPV4_FORWARD});
  if (check_file.is_open()) {
    char val;
    check_file >> val;
    if (val == '1') {
      trace(verbosity::debug, "IP forwarding already enabled");
      return ok{};
    }
  }

  std::ofstream forward_file(std::string{constants::PROC_IPV4_FORWARD});
  if (!forward_file.is_open()) {
    return make_error("Could not open " +
                      std::string{constants::PROC_IPV4_FORWARD} + ": " +
                      linux::get_errno_string());
  }

  forward_file << "1\n";
  if (!forward_file.good()) {
    return make_error("Failed to write to " +
                      std::string{constants::PROC_IPV4_FORWARD} + ": " +
                      linux::get_errno_string());
  }

  trace(verbosity::info, "Enabled IP forwarding");

  return ok{};
}

fn network_configurator::initial_setup() -> error_or<ok> {
  if (m_initial_setup_done) {
    trace(verbosity::debug, "Network already configured");
    return ok{};
  }

  m_default_iface = unwrap(detect_default_interface());

  let del_result = m_netlinker.delete_link(m_netlinker.get_veth_host_name());
  if (!del_result.is_err()) {
    trace(verbosity::debug, "Deleted existing veth pair `{}`",
          m_netlinker.get_veth_host_name());
  }

  unwrap(enable_ip_forward());

  trace(verbosity::info, "Creating veth pair: `{}` <-> `{}`",
        m_netlinker.get_veth_host_name(), m_netlinker.get_veth_ns_name());

  unwrap(m_netlinker.create_veth_pair(m_netlinker.get_veth_host_name(),
                                      m_netlinker.get_veth_ns_name()));

  unwrap(m_netlinker.add_address(m_netlinker.get_veth_host_name(),
                                 m_subnet.host_ip(),
                                 constants::SUBNET_PREFIX_LEN));

  unwrap(m_netlinker.set_link_up(m_netlinker.get_veth_host_name()));

  unwrap(m_netfilterer.setup_nat(m_default_iface, m_subnet.to_string()));

  unwrap(m_netfilterer.setup_forward(m_netlinker.get_veth_host_name()));

  m_initial_setup_done = true;
  trace(verbosity::info, "Network configuration complete for {}",
        m_subnet.to_string());

  return ok{};
}

fn network_configurator::finish_setup(pid_t daemon_pid) -> error_or<ok> {
  if (!m_initial_setup_done)
    return make_error("Initial setup not done.");

  // Moving an interface resets its link state, so set_link_up before the move
  // is useless. Move first, then configure from inside the daemon namespace.
  unwrap(m_netlinker.move_to_namespace(m_netlinker.get_veth_ns_name(),
                                       daemon_pid));

  int orig_ns_fd =
      unwrap(linux::oo_open(constants::PROC_SELF_NS_NET.data(), O_RDONLY));
  defer { unused(linux::oo_close(orig_ns_fd)); };

  let daemon_ns_path = "/proc/" + std::to_string(daemon_pid) + "/ns/net";
  int daemon_ns_fd = unwrap(linux::oo_open(daemon_ns_path.c_str(), O_RDONLY));
  defer { unused(linux::oo_close(daemon_ns_fd)); };

  unwrap(oo_linux_syscall(setns, daemon_ns_fd, CLONE_NEWNET));
  defer { unused(oo_linux_syscall(setns, orig_ns_fd, CLONE_NEWNET)); };

  netlinker ns_linker{m_ns};
  unwrap(ns_linker.set_link_up("lo"));
  unwrap(ns_linker.add_address(m_netlinker.get_veth_ns_name(), m_subnet.ns_ip(),
                               constants::SUBNET_PREFIX_LEN));
  unwrap(ns_linker.set_link_up(m_netlinker.get_veth_ns_name()));
  unwrap(ns_linker.add_route("0.0.0.0", 0, m_subnet.host_ip()));

  m_setup_done = true;
  return ok{};
}

fn network_configurator::cleanup() -> error_or<ok> {
  trace(verbosity::info, "Cleaning up network for {}", m_subnet.to_string());

  unused(m_netfilterer.cleanup());

  let del_result = m_netlinker.cleanup();

  return ok{};
}

fn network_configurator::save() const -> error_or<ok> {
  let ns_path = unwrap(m_ns.get_path());
  let net_path = ns_path / NET_FILE;

  std::ofstream file(net_path);
  if (!file.is_open()) {
    return make_error("Could not open network file for writing: " +
                      net_path.string() + ": " + linux::get_errno_string());
  }

  file << "# Network state\n";
  file << "subnet_octet=" << static_cast<u32>(m_subnet.third_octet) << "\n";
  file << "veth_host=" << m_netlinker.get_veth_host_name() << "\n";
  file << "veth_ns=" << m_netlinker.get_veth_ns_name() << "\n";

  if (!file.good()) {
    return make_error("Error writing to network file");
  }

  trace(verbosity::debug, "Saved network state to {}", net_path.string());
  return ok{};
}

fn network_configurator::load() -> error_or<ok> {
  let ns_path = unwrap(m_ns.get_path());
  let net_path = ns_path / NET_FILE;

  std::ifstream file(net_path);
  if (!file.is_open()) {
    return make_error("Could not open network file: " + net_path.string() +
                      ": " + linux::get_errno_string());
  }

  u8 subnet_octet = 0;
  std::string veth_host;
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

    if (key == "subnet_octet") {
      subnet_octet = static_cast<u8>(std::stoul(value));
    } else if (key == "veth_host") {
      veth_host = value;
    }
  }

  m_subnet = subnet{subnet_octet};
  m_netlinker.set_veth_host_name(veth_host);

  trace(verbosity::debug, "Loaded network state from {}", net_path.string());
  return ok{};
}

} // namespace oo
