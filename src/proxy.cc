#include "proxy.hh"

#include "oo_proxy.hh"
#include "squid_proxy.hh"

#include <arpa/inet.h>
#include <cstdlib>

namespace oo {

fn endpoint::parse(std::string_view text) -> error_or<endpoint> {
  let colon = text.rfind(':');
  if (colon == std::string_view::npos) {
    return make_error("Proxy address must be <ip>:<port>: " +
                      std::string{text});
  }

  std::string host{text.substr(0, colon)};
  std::string port_str{text.substr(colon + 1)};

  if (host.empty()) {
    return make_error("Proxy address is missing a host: " + std::string{text});
  }

  struct in_addr addr;
  if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
    return make_error("Proxy host must be an IPv4 address: " + host);
  }

  if (port_str.empty()) {
    return make_error("Proxy address is missing a port: " + std::string{text});
  }

  char *end = nullptr;
  let parsed = strtoul(port_str.c_str(), &end, 10);
  if (end == port_str.c_str() || *end != '\0') {
    return make_error("Invalid proxy port: " + port_str);
  }
  if (parsed < 1 || parsed > 65535) {
    return make_error("Proxy port must be between 1 and 65535: " + port_str);
  }

  return endpoint{std::move(host), static_cast<u16>(parsed)};
}

fn endpoint::to_string() const -> std::string {
  return host + ":" + std::to_string(port);
}

fn parse_proxy_backend(std::string_view name) -> error_or<proxy_backend_kind> {
  if (name == "builtin") {
    return proxy_backend_kind::builtin;
  }
  if (name == "squid") {
    return proxy_backend_kind::squid;
  }
  return make_error("Unknown proxy backend '" + std::string{name} +
                    "'. Valid backends are 'builtin' and 'squid'.");
}

fn make_proxy(proxy_backend_kind kind, linux_namespace &ns, pid_t daemon_pid)
    -> std::unique_ptr<proxy> {
  switch (kind) {
  case proxy_backend_kind::builtin:
    return std::make_unique<oo_proxy>(ns, daemon_pid);
  case proxy_backend_kind::squid:
    return std::make_unique<squid_proxy>(ns);
  }
  unreachable();
}

} // namespace oo
