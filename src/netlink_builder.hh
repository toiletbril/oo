#pragma once

#include "common.hh"

#include <cstring>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/types.h>

namespace oo {

// Helper to get tail of netlink message
#define NLMSG_TAIL(nmsg)                                                       \
  ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

class netlink_builder
{
public:
  netlink_builder(struct nlmsghdr *hdr, usize max_len)
      : m_hdr(hdr), m_max_len(max_len)
  {}

  fn add_attr(u16 type, const void *data, usize len) -> void
  {
    // SECURITY: abort on buffer overflow rather than silently corrupt the
    // heap-adjacent message buffer. m_max_len is the size of the buffer the
    // header lives in, so every growing write must fit within it.
    usize rta_len = RTA_LENGTH(len);
    usize new_len = NLMSG_ALIGN(m_hdr->nlmsg_len) + RTA_ALIGN(rta_len);
    insist(new_len <= m_max_len,
           "netlink_builder: attribute would overflow message buffer");
    struct rtattr *rta = NLMSG_TAIL(m_hdr);
    rta->rta_type = type;
    rta->rta_len = rta_len;
    if (len > 0) std::memcpy(RTA_DATA(rta), data, len);
    m_hdr->nlmsg_len = new_len;
  }

  fn add_attr_str(u16 type, std::string_view str) -> void
  {
    add_attr(type, str.data(), str.length() + 1);
  }

  template <typename T>
  fn add_attr_pod(u16 type, const T &val) -> void
  {
    add_attr(type, &val, sizeof(T));
  }

  fn add_attr_u32(u16 type, u32 v) -> void { add_attr_pod(type, v); }
  fn add_attr_in_addr(u16 type, struct in_addr a) -> void
  {
    add_attr_pod(type, a);
  }
  fn add_attr_pid(u16 type, pid_t p) -> void { add_attr_pod(type, p); }

  fn begin_nested(u16 type) -> struct rtattr *
  {
    struct rtattr *nest = NLMSG_TAIL(m_hdr);
    add_attr(type, nullptr, 0);
    return nest;
  }

  fn end_nested(struct rtattr *nest) -> void
  {
    nest->rta_len = (char *) NLMSG_TAIL(m_hdr) - (char *) nest;
  }

  fn add_raw_to_len(usize len) -> void
  {
    insist(m_hdr->nlmsg_len + len <= m_max_len,
           "netlink_builder: raw length addition would overflow buffer");
    m_hdr->nlmsg_len += len;
  }

private:
  struct nlmsghdr *m_hdr;
  usize m_max_len;
};

} // namespace oo
