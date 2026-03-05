#pragma once

#include "common.hh"
#include "error.hh"

namespace oo {

class netlink_socket {
public:
  netlink_socket();
  ~netlink_socket();

  netlink_socket(const netlink_socket &) = delete;
  netlink_socket &operator=(const netlink_socket &) = delete;

  fn get_fd() const -> int { return m_sock; }
  fn is_open() const -> bool { return m_sock >= 0; }

  fn send_message(const void *data, usize len) -> error_or<ok>;
  fn recv_message(void *buf, usize buf_size) -> error_or<usize>;

private:
  int m_sock = -1;
  std::string m_init_error;

  fn open() -> error_or<ok>;
  fn close() -> void;
};

} // namespace oo
