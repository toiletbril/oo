#pragma once

#include "common.hh"
#include "error.hh"

#include <string_view>

namespace oo {

class netlink_socket {
public:
  netlink_socket();
  ~netlink_socket();

  netlink_socket(const netlink_socket &) = delete;
  netlink_socket &operator=(const netlink_socket &) = delete;

  [[nodiscard]] fn get_fd() const -> int { return m_sock; }
  [[nodiscard]] fn is_open() const -> bool { return m_sock >= 0; }

  [[nodiscard]] fn send_message(const void *data, usize len) -> error_or<ok>;
  [[nodiscard]] fn recv_message(void *buf, usize buf_size) -> error_or<usize>;

  // Send a request and wait for a single ACK, returning on NLMSG_ERROR or
  // the first non-error message. Used by the link/addr/route single-ack
  // operations. `op` names the operation for the error message.
  [[nodiscard]] fn transact(void *req, usize req_len, std::string_view op)
      -> error_or<ok>;

  // Send a request and drain responses until NLMSG_DONE or an error. Used
  // by create-with-EXCL operations that set NLM_F_ACK and may return
  // multiple messages before DONE.
  [[nodiscard]] fn transact_loop(void *req, usize req_len, std::string_view op)
      -> error_or<ok>;

private:
  int m_sock = -1;
  std::string m_init_error;

  fn open() -> error_or<ok>;
  fn close() -> void;
};

} // namespace oo
