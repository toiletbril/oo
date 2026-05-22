#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "linux_util.hh"
#include "proxy.hh"

#include <string_view>
#include <sys/types.h>

namespace oo {

// Built-in in-process forward proxy. It accepts HTTP requests in absolute form
// and tunnels HTTPS through the CONNECT method, forking one child per
// connection so a slow peer cannot stall the others. It accepts only clients
// inside the oo address range and exits when its namespace daemon dies.
class oo_proxy : public proxy {
public:
  oo_proxy(linux_namespace &ns, pid_t daemon_pid)
      : m_ns(ns), m_daemon_pid(daemon_pid) {}

  [[nodiscard]] fn prepare(const endpoint &bind) -> error_or<ok> override;
  [[nodiscard]] fn run() -> error_or<ok> override;

private:
  linux_namespace &m_ns;
  pid_t m_daemon_pid;
  linux::oo_fd m_listen_fd;

  [[nodiscard]] fn handle_client(linux::oo_fd client) -> error_or<ok>;
};

} // namespace oo
