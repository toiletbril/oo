#include "netlinker.hh"

#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"
#include "netlink_builder.hh"

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace oo {

// Request templates. Each function that builds a netlink request produces a
// fixed-layout struct with nlmsghdr + family-specific header + variable
// attribute buffer. The sizes below are chosen to fit the largest attribute
// payload used by that request kind.
template <usize ExtraBytes> struct link_request {
  struct nlmsghdr n;
  struct ifinfomsg i;
  char buf[ExtraBytes];
};

template <usize ExtraBytes> struct addr_request {
  struct nlmsghdr n;
  struct ifaddrmsg a;
  char buf[ExtraBytes];
};

template <usize ExtraBytes> struct route_request {
  struct nlmsghdr n;
  struct rtmsg r;
  char buf[ExtraBytes];
};

namespace {

fn init_link_req(let &req, u16 type, u16 flags, u32 ifindex = 0) -> void {
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_type = type;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = ifindex;
}

fn init_addr_req(let &req, u16 type, u16 flags, u32 ifindex, u8 plen) -> void {
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_type = type;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
  req.a.ifa_family = AF_INET;
  req.a.ifa_prefixlen = plen;
  req.a.ifa_index = ifindex;
}

fn init_route_req(let &req, u16 type, u16 flags, u8 dst_len) -> void {
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_type = type;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
  req.r.rtm_family = AF_INET;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_protocol = RTPROT_STATIC;
  req.r.rtm_scope = RT_SCOPE_UNIVERSE;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_dst_len = dst_len;
}

} // namespace

netlinker::netlinker(linux_namespace &ns)
    : m_ns(ns), m_sock(), m_cleaned_up(false) {
  generate_veth_names();
  insist(!m_veth_host.empty() && !m_veth_ns.empty(),
         "veth names must be generated from a non-empty namespace name");
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
  insist(!ifname.empty() && ifname.size() < IFNAMSIZ,
         "interface name must be non-empty and fit in IFNAMSIZ");
  let i =
      unwrap(oo_non_zero(if_nametoindex(ifname.data()),
                         "Interface not found: `" + std::string{ifname} + "`"));
  trace(verbosity::debug, "{}", i);

  return i;
}

fn netlinker::create_veth_pair(std::string_view host_name,
                               std::string_view ns_name) -> error_or<ok> {
  link_request<1024> req{};
  init_link_req(req, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);

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

  unwrap(m_sock.transact_loop(&req, req.n.nlmsg_len, "creating veth"));

  trace(verbosity::info, "Created veth pair: `{}` <-> `{}`", host_name,
        ns_name);

  return ok{};
}

fn netlinker::move_to_namespace(std::string_view ifname, pid_t target_pid)
    -> error_or<ok> {
  let ifindex = unwrap(get_ifindex(ifname));

  link_request<256> req{};
  init_link_req(req, RTM_NEWLINK, 0, ifindex);

  netlink_builder builder(&req.n, sizeof(req));
  builder.add_attr_pid(IFLA_NET_NS_PID, target_pid);

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "moving interface"));

  trace(verbosity::info, "Moved interface `{}` to namespace PID `{}`", ifname,
        target_pid);

  return ok{};
}

fn netlinker::add_address(std::string_view ifname, std::string_view ip,
                          u8 prefix_len) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname, ip, prefix_len);

  let ifindex = unwrap(get_ifindex(ifname));

  trace(verbosity::info, "Adding address {}", std::string{ip});

  insist(!ip.empty() && ip.find('\0') == std::string_view::npos,
         "IP address must be a non-empty C string. Fuck you");
  struct in_addr addr;
  if (inet_pton(AF_INET, ip.data(), &addr) != 1) {
    return make_error("Invalid IP address: " + std::string{ip});
  }

  addr_request<256> req{};
  init_addr_req(req, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, ifindex,
                prefix_len);

  netlink_builder builder(&req.n, sizeof(req));
  builder.add_attr_in_addr(IFA_LOCAL, addr);
  builder.add_attr_in_addr(IFA_ADDRESS, addr);

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "adding address"));

  trace(verbosity::info, "Added address `{}/{}` to `{}`", ip, prefix_len,
        ifname);

  return ok{};
}

fn netlinker::add_route(std::string_view dest_ip, u8 prefix_len,
                        std::string_view gateway) -> error_or<ok> {
  trace_variables(verbosity::debug, dest_ip, prefix_len, gateway);

  route_request<256> req{};
  init_route_req(req, RTM_NEWROUTE, NLM_F_CREATE, prefix_len);

  netlink_builder builder(&req.n, sizeof(req));

  if (prefix_len > 0 && !dest_ip.empty() &&
      dest_ip != constants::DEFAULT_GATEWAY_IP) {
    insist(dest_ip.find('\0') == std::string_view::npos,
           "destination IP must be a non-empty C string");
    struct in_addr dst;
    if (inet_pton(AF_INET, dest_ip.data(), &dst) != 1) {
      return make_error("Invalid destination IP: " + std::string{dest_ip});
    }
    builder.add_attr_in_addr(RTA_DST, dst);
  }

  insist(!gateway.empty() && gateway.find('\0') == std::string_view::npos,
         "gateway IP must be a non-empty C string");
  struct in_addr gw;
  if (inet_pton(AF_INET, gateway.data(), &gw) != 1) {
    return make_error("Invalid gateway IP: " + std::string{gateway});
  }
  builder.add_attr_in_addr(RTA_GATEWAY, gw);

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "adding route"));

  trace(verbosity::info, "Added route `{}/{}` via `{}`", dest_ip, prefix_len,
        gateway);

  return ok{};
}

fn netlinker::set_link_up(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  link_request<0> req{};
  init_link_req(req, RTM_NEWLINK, 0, ifindex);
  req.i.ifi_flags = IFF_UP;
  req.i.ifi_change = IFF_UP;

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "setting link up"));

  trace(verbosity::info, "Set link `{}` up", ifname);

  return ok{};
}

fn netlinker::set_link_down(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  link_request<0> req{};
  init_link_req(req, RTM_NEWLINK, 0, ifindex);
  req.i.ifi_flags = 0;
  req.i.ifi_change = IFF_UP;

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "setting link down"));

  trace(verbosity::info, "Set link `{}` down", ifname);

  return ok{};
}

fn netlinker::delete_link(std::string_view ifname) -> error_or<ok> {
  trace_variables(verbosity::debug, ifname);

  let ifindex = unwrap(get_ifindex(ifname));

  link_request<0> req{};
  init_link_req(req, RTM_DELLINK, 0, ifindex);

  unwrap(m_sock.transact(&req, req.n.nlmsg_len, "deleting link"));

  trace(verbosity::info, "Deleted link `{}`", ifname);

  return ok{};
}

fn netlinker::cleanup() -> error_or<ok> {
  if (m_cleaned_up) {
    return ok{};
  }

  if (!m_sock.is_open()) {
    m_cleaned_up = true;
    trace(verbosity::error, "Socket closed, skipping veth deletion");
    return ok{};
  }

  insist(!m_veth_host.empty(),
         "cleanup would call delete_link with an empty interface name");
  let del_result = delete_link(m_veth_host);
  if (del_result.is_err()) {
    trace(verbosity::debug, "Failed to delete veth (may not exist): {}",
          del_result.get_error().get_reason());
  }

  m_cleaned_up = true;

  return ok{};
}

} // namespace oo
