#include "netlinker.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"
#include "netlink_builder.hh"

#include <arpa/inet.h>
#include <cstring>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace oo {

netlinker::netlinker(linux_namespace &ns)
    : m_ns(ns), m_sock(), m_cleaned_up(false) {
  generate_veth_names();
}

fn netlinker::generate_veth_names() -> void {
  m_veth_host = std::string{constants::VETH_NAME_PREFIX} + m_ns.get_name() +
                std::string{constants::VETH_HOST_SUFFIX};
  m_veth_ns = std::string{constants::VETH_NAME_PREFIX} + m_ns.get_name() +
              std::string{constants::VETH_NS_SUFFIX};
}

netlinker::~netlinker() = default;

fn netlinker::get_ifindex(std::string_view ifname) -> error_or<u32> {
  trace_variables(verbosity::debug, ifname);
  let i =
      unwrap(oo_non_zero(if_nametoindex(ifname.data()),
                         "Interface not found: `" + std::string{ifname} + "`"));
  trace(verbosity::debug, "{}", i);
  return i;
}

fn netlinker::create_veth_pair(std::string_view host_name,
                               std::string_view ns_name) -> error_or<ok> {
  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[1024];
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWLINK;
  req.n.nlmsg_seq = 1;
  req.n.nlmsg_pid = 0;
  req.i.ifi_family = AF_UNSPEC;

  netlink_builder builder(&req.n, sizeof(req));

  builder.add_attr_str(IFLA_IFNAME, host_name);

  let linkinfo = builder.begin_nested(IFLA_LINKINFO);
  builder.add_attr(IFLA_INFO_KIND, constants::VETH_KIND.data(),
                   constants::VETH_KIND.size());

  let data = builder.begin_nested(IFLA_INFO_DATA);
  let peer = builder.begin_nested(VETH_INFO_PEER);
  builder.add_raw_to_len(sizeof(struct ifinfomsg));
  builder.add_attr_str(IFLA_IFNAME, ns_name);
  builder.end_nested(peer);

  builder.end_nested(data);
  builder.end_nested(linkinfo);

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  for (;;) {
    let len = unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

    struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);

    if (resp->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr *err =
          reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
      if (err->error != 0) {
        return make_error("Netlink error creating veth: " +
                          linux::get_error_string(-err->error));
      }
      break;
    }

    if (resp->nlmsg_type == NLMSG_DONE) {
      break;
    }
  }

  trace(verbosity::info, "Created veth pair: `{}` <-> `{}`", host_name,
        ns_name);
  return ok{};
}

fn netlinker::move_to_namespace(std::string_view ifname, pid_t target_pid)
    -> error_or<ok> {
  let ifindex = unwrap(get_ifindex(ifname));

  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[256];
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWLINK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = ifindex;

  struct rtattr *rta = reinterpret_cast<struct rtattr *>(req.buf);
  rta->rta_type = IFLA_NET_NS_PID;
  rta->rta_len = RTA_LENGTH(sizeof(pid_t));
  std::memcpy(RTA_DATA(rta), &target_pid, sizeof(pid_t));
  req.n.nlmsg_len += rta->rta_len;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error moving interface: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Moved interface `{}` to namespace PID `{}`", ifname,
        target_pid);
  return ok{};
}

fn netlinker::add_address(std::string_view ifname, std::string_view ip,
                          u8 prefix_len) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname, ip, prefix_len);

  let ifindex = unwrap(get_ifindex(ifname));

  struct {
    struct nlmsghdr n;
    struct ifaddrmsg a;
    char buf[256];
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWADDR;
  req.a.ifa_family = AF_INET;
  req.a.ifa_prefixlen = prefix_len;
  req.a.ifa_index = ifindex;

  trace(verbosity::info, "Adding address {}", std::string{ip});

  struct in_addr addr;
  if (inet_pton(AF_INET, ip.data(), &addr) != 1) {
    return make_error("Invalid IP address: " + std::string{ip});
  }

  struct rtattr *rta = reinterpret_cast<struct rtattr *>(req.buf);
  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
  std::memcpy(RTA_DATA(rta), &addr, sizeof(struct in_addr));
  req.n.nlmsg_len += rta->rta_len;

  rta = reinterpret_cast<struct rtattr *>(reinterpret_cast<char *>(&req.n) +
                                          NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_type = IFA_ADDRESS;
  rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
  std::memcpy(RTA_DATA(rta), &addr, sizeof(struct in_addr));
  req.n.nlmsg_len += rta->rta_len;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error adding address: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Added address `{}/{}` to `{}`", ip, prefix_len,
        ifname);
  return ok{};
}

fn netlinker::add_route(std::string_view dest_ip, u8 prefix_len,
                        std::string_view gateway) -> error_or<ok> {
  trace_variables(verbosity::debug, dest_ip, prefix_len, gateway);

  struct {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[256];
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWROUTE;
  req.r.rtm_family = AF_INET;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_protocol = RTPROT_STATIC;
  req.r.rtm_scope = RT_SCOPE_UNIVERSE;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_dst_len = prefix_len;

  char *buf_ptr = req.buf;

  if (prefix_len > 0 && !dest_ip.empty() &&
      dest_ip != constants::DEFAULT_GATEWAY_IP) {
    struct in_addr dst;
    if (inet_pton(AF_INET, dest_ip.data(), &dst) != 1) {
      return make_error("Invalid destination IP: " + std::string{dest_ip});
    }

    struct rtattr *rta = reinterpret_cast<struct rtattr *>(buf_ptr);
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    std::memcpy(RTA_DATA(rta), &dst, sizeof(struct in_addr));
    req.n.nlmsg_len += rta->rta_len;
    buf_ptr += rta->rta_len;
  }

  struct in_addr gw;
  if (inet_pton(AF_INET, gateway.data(), &gw) != 1) {
    return make_error("Invalid gateway IP: " + std::string{gateway});
  }

  struct rtattr *rta = reinterpret_cast<struct rtattr *>(buf_ptr);
  rta->rta_type = RTA_GATEWAY;
  rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
  std::memcpy(RTA_DATA(rta), &gw, sizeof(struct in_addr));
  req.n.nlmsg_len += rta->rta_len;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error adding route: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Added route `{}/{}` via `{}`", dest_ip, prefix_len,
        gateway);
  return ok{};
}

fn netlinker::set_link_up(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWLINK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = ifindex;
  req.i.ifi_flags = IFF_UP;
  req.i.ifi_change = IFF_UP;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error setting link up: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Set link `{}` up", ifname);

  return ok{};
}

fn netlinker::set_link_down(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_type = RTM_NEWLINK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = ifindex;
  req.i.ifi_flags = 0;
  req.i.ifi_change = IFF_UP;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error setting link down: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Set link `{}` down", ifname);
  return ok{};
}

fn netlinker::delete_link(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req{};

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_type = RTM_DELLINK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = ifindex;

  unwrap(m_sock.send_message(&req, req.n.nlmsg_len));

  char resp_buf[constants::NETLINK_RESP_BUF_SIZE];
  unwrap(m_sock.recv_message(resp_buf, sizeof(resp_buf)));

  struct nlmsghdr *resp = reinterpret_cast<struct nlmsghdr *>(resp_buf);
  if (resp->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err =
        reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
    if (err->error != 0) {
      return make_error("Netlink error deleting link: `" +
                        linux::get_error_string(-err->error) + "`");
    }
  }

  trace(verbosity::info, "Deleted link `{}`", ifname);

  return ok{};
}

fn netlinker::cleanup() -> error_or<ok> {
  if (m_cleaned_up) {
    return ok{};
  }

  if (!m_sock.is_open()) {
    m_cleaned_up = true;
    trace(verbosity::debug, "Socket closed, skipping veth deletion");
    return ok{};
  }

  let del_result = delete_link(m_veth_host);
  if (del_result.is_err()) {
    trace(verbosity::debug, "Failed to delete veth (may not exist): {}",
          del_result.get_error().get_reason());
  }

  m_cleaned_up = true;
  return ok{};
}

} // namespace oo
