#pragma once

#include "common.hh"

#include <filesystem>
#include <string_view>

namespace oo {

namespace constants {

// Runtime directories
inline constexpr std::string_view OO_RUN_DIR = "/var/run/oo";

// Proc filesystem paths
inline constexpr std::string_view PROC_SELF_EXE = "/proc/self/exe";
inline constexpr std::string_view PROC_NET_ROUTE = "/proc/net/route";
inline constexpr std::string_view PROC_IPV4_FORWARD =
    "/proc/sys/net/ipv4/ip_forward";

// System configuration paths
inline constexpr std::string_view ETC_RESOLV_CONF = "/etc/resolv.conf";
inline constexpr std::string_view ETC_NSSWITCH_CONF = "/etc/nsswitch.conf";

// State file names
inline constexpr std::string_view IP_POOL_FILE = "ip-pool.ini";
inline constexpr std::string_view STATE_FILE = "state.ini";
inline constexpr std::string_view RESOLV_CONF_FILE = "resolv.conf";
inline constexpr std::string_view NSSWITCH_CONF_FILE = "nsswitch.conf";

// File permissions
inline constexpr mode_t PERM_WORLD_RWX = 0777;
inline constexpr mode_t PERM_USER_RWX = 0700;

// Network constants
inline constexpr std::string_view IP_PREFIX = "10.0.";
inline constexpr u8 SUBNET_PREFIX_LEN = 30;
inline constexpr usize SUBNET_POOL_SIZE = 256;

// Timeouts and intervals (milliseconds)
inline constexpr int POLL_TIMEOUT_MS = 5000;
inline constexpr int GRACEFUL_SHUTDOWN_SLEEP_MS = 100;
inline constexpr int FORCEFUL_SHUTDOWN_SLEEP_MS = 500;
inline constexpr int GRACEFUL_SHUTDOWN_ITERATIONS = 50;

// Buffer sizes
inline constexpr usize BUFFER_SIZE_4K = 4096;
inline constexpr usize BUFFER_SIZE_1K = 1024;
inline constexpr usize BUFFER_SIZE_256 = 256;

// Netlink buffer sizes
inline constexpr usize NETLINK_BUFFER_SIZE = BUFFER_SIZE_4K;
inline constexpr usize NETLINK_REQUEST_BUFFER = BUFFER_SIZE_1K;
inline constexpr usize NETLINK_SMALL_BUFFER = BUFFER_SIZE_256;

} // namespace constants

} // namespace oo
