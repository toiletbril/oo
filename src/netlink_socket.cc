#include "netlink_socket.hh"

#include "constants.hh"
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
    return make_error("Failed to create netlink socket: " +
                      linux::get_errno_string());
  }
  m_sock = sock_result.get_value();
  insist(m_sock >= 0, "socket() succeeded but returned a negative descriptor");

  struct timeval tv{};
  tv.tv_sec = constants::NETLINK_TIMEOUT_SEC;
  tv.tv_usec = 0;
  let timeout_result = oo_linux_syscall(setsockopt, m_sock, SOL_SOCKET,
                                        SO_RCVTIMEO, &tv, sizeof(tv));
  if (timeout_result.is_err()) {
    unwrap(linux::oo_close(m_sock));
    m_sock = -1;
    insist(m_sock == -1, "closed socket must leave m_sock in the sentinel");
    return make_error("Failed to set netlink socket timeout: " +
                      linux::get_errno_string());
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
    insist(m_sock == -1, "closed socket must leave m_sock in the sentinel");
    return make_error("Failed to bind netlink socket: " +
                      linux::get_errno_string());
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

// SECURITY: Walk the received buffer with NLMSG_OK before dereferencing
// fields. A short read, a multi-part message, or a malformed nlmsg_len
// would otherwise lead to an out-of-bounds read of the stack buffer. The
// length argument must be an lvalue because NLMSG_NEXT mutates it.
fn netlink_socket::transact(void *req, usize req_len, std::string_view op)
    -> error_or<ok> {
  unwrap(send_message(req, req_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  usize recv_len = unwrap(recv_message(resp_buf, sizeof(resp_buf)));
  unsigned int len = static_cast<unsigned int>(recv_len);

  for (struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
       NLMSG_OK(resp, len); resp = NLMSG_NEXT(resp, len)) {
    if (resp->nlmsg_type == NLMSG_ERROR) {
      if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        return make_error("Truncated netlink error for " + std::string{op});
      }
      struct nlmsgerr *err =
          reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
      if (err->error != 0) {
        return make_error("Netlink error " + std::string{op} + ": " +
                          linux::get_error_string(-err->error));
      }
    }
  }

  return ok{};
}

fn netlink_socket::transact_loop(void *req, usize req_len, std::string_view op)
    -> error_or<ok> {
  unwrap(send_message(req, req_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  for (;;) {
    usize recv_len = unwrap(recv_message(resp_buf, sizeof(resp_buf)));
    unsigned int len = static_cast<unsigned int>(recv_len);
    bool terminal = false;

    for (struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
         NLMSG_OK(resp, len); resp = NLMSG_NEXT(resp, len)) {
      if (resp->nlmsg_type == NLMSG_ERROR) {
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
          return make_error("Truncated netlink error for " + std::string{op});
        }
        struct nlmsgerr *err =
            reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
        if (err->error != 0) {
          return make_error("Netlink error " + std::string{op} + ": " +
                            linux::get_error_string(-err->error));
        }
        terminal = true;
        break;
      }

      if (resp->nlmsg_type == NLMSG_DONE) {
        terminal = true;
        break;
      }
    }

    if (terminal)
      break;
  }

  return ok{};
}

} // namespace oo
