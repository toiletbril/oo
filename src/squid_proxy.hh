#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "proxy.hh"

#include <string>
#include <string_view>

namespace oo {

// Forward proxy backed by the system squid. prepare() locates the squid binary
// and writes a generated config that binds inside the namespace. run() execs
// squid in the foreground, so the calling process becomes the squid process.
class squid_proxy : public proxy {
public:
  explicit squid_proxy(linux_namespace &ns) : m_ns(ns) {}

  [[nodiscard]] fn prepare(const endpoint &bind) -> error_or<ok> override;
  [[nodiscard]] fn run() -> error_or<ok> override;
  [[nodiscard]] fn name() const -> std::string_view override { return "squid"; }

private:
  linux_namespace &m_ns;
  std::string m_squid_path;
  std::string m_config_path;

  [[nodiscard]] static fn find_squid() -> error_or<std::string>;
};

} // namespace oo
