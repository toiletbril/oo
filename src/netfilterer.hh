#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"

#include <memory>
#include <string>
#include <vector>

namespace oo {

// Abstract firewall backend. Concrete subclasses implement NAT, forwarding
// and cleanup via their specific tooling (iptables-legacy, nftables, or a
// future in-process netlink implementation). The common fork+setuid(0)+exec
// dance lives in `run_privileged()` so only the rule construction differs.
class netfilterer_backend
{
public:
  virtual ~netfilterer_backend() = default;

  netfilterer_backend(const netfilterer_backend &) = delete;
  netfilterer_backend &operator=(const netfilterer_backend &) = delete;

  virtual fn setup_nat(std::string_view host_iface, std::string_view subnet)
      -> error_or<ok> = 0;
  virtual fn setup_forward(std::string_view host_iface) -> error_or<ok> = 0;
  virtual fn cleanup() -> error_or<ok> = 0;

protected:
  netfilterer_backend(linux_namespace &ns, std::string backend_path)
      : m_ns(ns), m_backend_path(std::move(backend_path))
  {}

  // Fork, setuid(0), drop capabilities, execvp the backend binary and
  // waitpid. argv[0] must be the absolute backend path (not a bare name) to
  // prevent PATH-hijacking of the setuid child. Called by setup/cleanup.
  fn run_privileged(const std::vector<std::string> &argv) -> error_or<ok>;

  linux_namespace &m_ns;
  std::string m_backend_path;
  std::vector<std::string> m_cleanup_cmds;
  bool m_cleaned_up{false};
};

class iptables_legacy_backend : public netfilterer_backend
{
public:
  iptables_legacy_backend(linux_namespace &ns, std::string backend_path)
      : netfilterer_backend(ns, std::move(backend_path))
  {}

  fn setup_nat(std::string_view host_iface, std::string_view subnet)
      -> error_or<ok> override;
  fn setup_forward(std::string_view host_iface) -> error_or<ok> override;
  fn cleanup() -> error_or<ok> override;
};

class nftables_backend : public netfilterer_backend
{
public:
  nftables_backend(linux_namespace &ns, std::string backend_path)
      : netfilterer_backend(ns, std::move(backend_path))
  {}

  fn setup_nat(std::string_view host_iface, std::string_view subnet)
      -> error_or<ok> override;
  fn setup_forward(std::string_view host_iface) -> error_or<ok> override;
  fn cleanup() -> error_or<ok> override;
};

// Facade that selects an available backend at construction and forwards
// setup/cleanup to it. A future self-routed backend (writing rules via
// netlink directly) can slot in alongside the existing two.
class netfilterer
{
public:
  netfilterer(linux_namespace &ns);
  ~netfilterer() = default;

  fn setup_nat(std::string_view host_iface, std::string_view subnet)
      -> error_or<ok>;
  fn setup_forward(std::string_view host_iface) -> error_or<ok>;
  fn cleanup() -> error_or<ok>;

private:
  std::unique_ptr<netfilterer_backend> m_impl;

  static fn detect(linux_namespace &ns) -> std::unique_ptr<netfilterer_backend>;
};

} // namespace oo
