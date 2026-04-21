#pragma once

#include "common.hh"

#include <filesystem>
#include <string_view>

namespace oo {

namespace constants {

inline constexpr std::string OO_RUN_DIR = "/var/run/oo";

// SECURITY: The oo binary runs as this dedicated system user for every
// runtime subcommand so ordinary DAC checks authorize writes under
// OO_RUN_DIR. The account is created by `oo init` with a locked password
// and a nologin shell. CAP_DAC_OVERRIDE is intentionally not held, so
// losing this account's ownership of OO_RUN_DIR bricks the tool until
// `oo init` is re-run.
inline constexpr std::string_view OORUNNER_NAME = "oorunner";
inline constexpr std::string_view OORUNNER_SHELL = "/usr/sbin/nologin";
inline constexpr std::string_view OORUNNER_GECOS = "oo runtime user";
inline constexpr std::string_view OORUNNER_HOME = "/nonexistent";

inline constexpr std::string PROC_SELF_EXE = "/proc/self/exe";
inline constexpr std::string PROC_NET_ROUTE = "/proc/net/route";
inline constexpr std::string_view PROC_IPV4_FORWARD =
    "/proc/sys/net/ipv4/ip_forward";

inline constexpr std::string_view IPTABLES_LEGACY_SBIN_PATH =
    "/usr/sbin/iptables-legacy";
inline constexpr std::string_view IPTABLES_LEGACY_BIN_PATH =
    "/sbin/iptables-legacy";
inline constexpr std::string_view NFT_SBIN_PATH = "/usr/sbin/nft";
inline constexpr std::string_view NFT_BIN_PATH = "/sbin/nft";

inline constexpr std::string_view IPTABLES_LEGACY_CMD = "iptables-legacy";
inline constexpr std::string_view NFT_CMD = "nft";

inline constexpr std::string_view ETC_RESOLV_CONF = "/etc/resolv.conf";
inline constexpr std::string_view ETC_NSSWITCH_CONF = "/etc/nsswitch.conf";

inline constexpr usize INI_MAX_LINE = 65536;

inline constexpr std::string IP_POOL_FILE = "ip-pool.ini";
inline constexpr std::string RESOLV_CONF_FILE = "resolv.conf";
inline constexpr std::string NSSWITCH_CONF_FILE = "nsswitch.conf";

inline constexpr std::string_view IP_PREFIX = "10.0.";
inline constexpr u8 DEFAULT_SUBNET_PREFIX_LEN = 30;
inline constexpr u8 MIN_SUBNET_PREFIX_LEN = 16;
inline constexpr u8 MAX_SUBNET_PREFIX_LEN = 30;
inline constexpr usize SUBNET_POOL_SIZE = 256;

inline constexpr usize GRACEFUL_SHUTDOWN_SLEEP_MS = 100;
inline constexpr usize FORCEFUL_SHUTDOWN_SLEEP_MS = 500;
inline constexpr usize GRACEFUL_SHUTDOWN_ITERATIONS = 50;

inline constexpr std::string_view DEFAULT_ROUTE_DEST = "00000000";
inline constexpr std::string_view DEFAULT_GATEWAY_IP = "0.0.0.0";

inline constexpr usize NETLINK_TIMEOUT_SEC = 5;
inline constexpr usize NETLINK_RESP_BUF_SIZE = 4096;

inline constexpr std::string_view VETH_NAME_PREFIX = "veth-";
inline constexpr std::string_view VETH_HOST_SUFFIX = "-host";
inline constexpr std::string_view VETH_NS_SUFFIX = "-ns";
inline constexpr std::string_view VETH_KIND = "veth";

inline constexpr std::string_view PROC_SELF_NS_NET = "/proc/self/ns/net";

inline constexpr std::string_view DAEMON_MSG_ERR = "err\n";
inline constexpr std::string_view DAEMON_MSG_OK = "ok:";
inline constexpr int DAEMON_SPAWN_TIMEOUT_MS = 5000;

} // namespace constants

} // namespace oo
