#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "proxy.hh"

#include <string_view>

namespace oo {

// Built-in in-process forward proxy. It accepts HTTP requests in absolute form
// and tunnels HTTPS through the CONNECT method, forking one child per
// connection so a slow peer cannot stall the others.
class oo_proxy : public proxy {
public:
  explicit oo_proxy(linux_namespace &ns) : m_ns(ns) {}

  [[nodiscard]] fn prepare(const endpoint &bind) -> error_or<ok> override;
  [[nodiscard]] fn run() -> error_or<ok> override;
  [[nodiscard]] fn name() const -> std::string_view override {
    return "builtin";
  }

private:
  linux_namespace &m_ns;
  linux::oo_fd m_listen_fd;

  [[nodiscard]] fn handle_client(linux::oo_fd client) -> error_or<ok>;
};

} // namespace oo
