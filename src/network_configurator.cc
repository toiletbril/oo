#include "network_configurator.hh"
#include "debug.hh"

#include <fstream>
#include <sstream>

namespace oo {

network_configurator::network_configurator(linux_namespace &ns, subnet s)
    : m_ns(ns), m_subnet(s) {
  m_netlinker = std::make_unique<netlinker>(ns);
  m_netfilterer = std::make_unique<netfilterer>(ns);
}

network_configurator::~network_configurator() = default;

fn network_configurator::generate_veth_names() -> void {
  m_veth_host = "veth-" + m_ns.get_name() + "-host";
  m_veth_ns = "veth-" + m_ns.get_name() + "-ns";
}

fn network_configurator::prepare_cleanup(std::string_view veth_host) -> void {
  m_veth_host = veth_host;
  m_initial_setup_done = true;
}

fn network_configurator::detect_default_interface() -> error_or<std::string> {
  std::ifstream route_file("/proc/net/route");
  if (!route_file.is_open()) {
    return make_error("Could not open /proc/net/route");
  }

  std::string line;
  std::getline(route_file, line);

  while (std::getline(route_file, line)) {
    std::istringstream iss(line);
    std::string iface, dest, gateway;

    if (!(iss >> iface >> dest >> gateway)) {
      continue;
    }

    if (dest == "00000000") {
      trace(verbosity::info, "Detected default interface: {}", iface);
      return iface;
    }
  }

  return make_error("Could not detect default network interface");
}

fn network_configurator::enable_ip_forward() -> error_or<ok> {
  const char *ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

  std::ifstream check_file(ip_forward_path);
  if (check_file.is_open()) {
    char val;
    check_file >> val;
    if (val == '1') {
      trace(verbosity::debug, "IP forwarding already enabled");
      return ok{};
    }
  }

  std::ofstream forward_file(ip_forward_path);
  if (!forward_file.is_open()) {
    return make_error("Could not open " + std::string{ip_forward_path});
  }

  forward_file << "1\n";
  if (!forward_file.good()) {
    return make_error("Failed to enable IP forwarding");
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

  generate_veth_names();

  let del_result = m_netlinker->delete_link(m_veth_host);
  if (!del_result.is_err()) {
    trace(verbosity::debug, "Deleted existing veth pair `{}`", m_veth_host);
  }

  unwrap(enable_ip_forward());

  trace(verbosity::info, "Creating veth pair: `{}` <-> `{}`", m_veth_host,
        m_veth_ns);
  unwrap(m_netlinker->create_veth_pair(m_veth_host, m_veth_ns));

  unwrap(m_netlinker->add_address(m_veth_host, m_subnet.host_ip(), 30));

  unwrap(m_netlinker->set_link_up(m_veth_host));

  unwrap(m_netfilterer->setup_nat(m_default_iface, m_subnet.to_string()));

  unwrap(m_netfilterer->setup_forward(m_veth_host));

  m_initial_setup_done = true;
  trace(verbosity::info, "Network configuration complete for {}",
        m_subnet.to_string());

  return ok{};
}

fn network_configurator::finish_setup(pid_t daemon_pid) -> error_or<ok> {
  if (!m_initial_setup_done)
    return make_error("Initial setup not done.");
  unwrap(m_netlinker->set_link_up(m_veth_ns));
  unwrap(m_netlinker->move_to_namespace(m_veth_ns, daemon_pid));
  m_setup_done = true;
  return ok{};
}

fn network_configurator::cleanup() -> error_or<ok> {
  if (!m_initial_setup_done) {
    return ok{};
  }

  trace(verbosity::info, "Cleaning up network for {}", m_subnet.to_string());

  m_netfilterer.reset();

  let del_result = m_netlinker->delete_link(m_veth_host);
  if (del_result.is_err()) {
    trace(verbosity::error, "Failed to delete veth: {}",
          del_result.get_error().get_reason());
  }

  m_initial_setup_done = false;
  return ok{};
}

} // namespace oo
