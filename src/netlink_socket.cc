#include "netlink_socket.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <linux/netlink.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace oo {

netlink_socket::netlink_socket() {
  let result = open();
  if (result.is_err()) {
    m_init_error = result.get_error().get_owned_reason();
    trace(verbosity::error, "Failed to open netlink socket: {}", m_init_error);
  }
}

netlink_socket::~netlink_socket() { close(); }

fn netlink_socket::open() -> error_or<ok> {
  let cap_result = linux::raise_capability(CAP_NET_ADMIN);
  if (cap_result.is_err()) {
    return make_error("Failed to raise CAP_NET_ADMIN capability. Try running "
                      "`sudo ./oo init` first");
  }
  trace(verbosity::debug, "Raised CAP_NET_ADMIN");

  let sock_result =
      oo_linux_syscall(socket, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock_result.is_err()) {
    return make_error(
        "Failed to create netlink socket. Ensure the kernel supports netlink");
  }
  m_sock = sock_result.get_value();

  struct timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  let timeout_result = oo_linux_syscall(setsockopt, m_sock, SOL_SOCKET,
                                        SO_RCVTIMEO, &tv, sizeof(tv));
  if (timeout_result.is_err()) {
    unwrap(linux::oo_close(m_sock));
    m_sock = -1;
    return make_error("Failed to set socket timeout");
  }

  struct sockaddr_nl addr{};
  addr.nl_family = AF_NETLINK;
  addr.nl_pad = 0;
  addr.nl_pid = 0;
  addr.nl_groups = 0;

  let bind_result = oo_linux_syscall(
      bind, m_sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
  if (bind_result.is_err()) {
    unwrap(linux::oo_close(m_sock));
    m_sock = -1;
    return make_error("Failed to bind netlink socket. Ensure you have network "
                      "admin permissions");
  }

  trace(verbosity::debug, "Opened netlink socket: {}", m_sock);
  return ok{};
}

fn netlink_socket::close() -> void {
  if (m_sock >= 0) {
    unused(linux::oo_close(m_sock));
    trace(verbosity::debug, "Closed netlink socket");
    m_sock = -1;
  }
}

fn netlink_socket::send_message(const void *data, usize len) -> error_or<ok> {
  trace_variables(verbosity::all, data, len);

  if (m_sock < 0) {
    return error{m_init_error};
  }

  let result = oo_linux_syscall(send, m_sock, data, len, 0);
  if (result.is_err()) {
    return make_error(
        "Failed to send netlink message. Socket may be closed or invalid");
  }
  return ok{};
}

fn netlink_socket::recv_message(void *buf, usize buf_size) -> error_or<usize> {
  trace_variables(verbosity::all, buf, buf_size);

  if (m_sock < 0) {
    return error{m_init_error};
  }

  let result = oo_linux_syscall(recv, m_sock, buf, buf_size, 0);
  if (result.is_err()) {
    return make_error(
        "Failed to receive netlink message. Socket may be closed or timed out");
  }
  return static_cast<usize>(result.get_value());
}

} // namespace oo
