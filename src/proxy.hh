#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"

#include <memory>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace oo {

// A bind address and port for a proxy listener, for example "0.0.0.0:8080".
struct endpoint {
  std::string host;
  u16 port{0};

  // Parse "<ipv4>:<port>". The host must be a literal IPv4 address and the
  // port must be in the range 1 to 65535.
  [[nodiscard]] static fn parse(std::string_view text) -> error_or<endpoint>;
  [[nodiscard]] fn to_string() const -> std::string;
};

enum class proxy_backend_kind : u8 {
  builtin,
  squid,
};

[[nodiscard]] fn parse_proxy_backend(std::string_view name)
    -> error_or<proxy_backend_kind>;

// Abstract forward proxy. A concrete backend binds a listener inside a network
// namespace and serves HTTP and HTTPS through that namespace's DNS and route.
// prepare() runs while the process is still privileged so a bind failure
// surfaces before the caller commits. run() blocks after privileges have been
// dropped and serves until terminated.
class proxy {
public:
  virtual ~proxy() = default;

  proxy(const proxy &) = delete;
  proxy &operator=(const proxy &) = delete;

  [[nodiscard]] virtual fn prepare(const endpoint &bind) -> error_or<ok> = 0;
  [[nodiscard]] virtual fn run() -> error_or<ok> = 0;
  [[nodiscard]] virtual fn name() const -> std::string_view = 0;

protected:
  proxy() = default;
};

// `daemon_pid` is the namespace daemon the proxy lives alongside. The built-in
// backend watches it and exits when it dies so the network namespace is not
// pinned by an orphaned proxy.
[[nodiscard]] fn make_proxy(proxy_backend_kind kind, linux_namespace &ns,
                            pid_t daemon_pid) -> std::unique_ptr<proxy>;

} // namespace oo
