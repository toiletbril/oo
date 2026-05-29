#pragma once

#include "common.hh"
#include "error.hh"
#include "linux_namespace.hh"
#include "network_configurator.hh"
#include "privilege_drop.hh"

#include <sys/types.h>

namespace oo {

// Stay attached to a running daemon until it dies, then tear the namespace
// down the same way `oo down` does. The caller must already have set up the
// namespace, called pw.su_oorunner, and released its ip_pool lock so this
// function does not block concurrent up, down, and touch on every namespace
// for the daemon's whole lifetime.
//
// monitor_pid is the pid returned by satan::spawn_daemon, which is the
// process group leader formed by the monitor's setsid. monitor_start_time
// is read from /proc and used to detect monitor exit even when the monitor
// is not a direct child of the calling process, as is the case in attach
// mode.
//
// proxy_pid and proxy_start_time refer to the optional namespace proxy
// spawned alongside the daemon. Pass 0 when no proxy is running. The
// forwarder process drops to the invoking user and signals both the daemon
// and the proxy groups on the way out so namespace teardown is safe.
//
// tail_from_end controls the starting position in the log files. Pass false
// for a freshly spawned daemon so the first bytes of output reach the
// terminal even when the daemon printed them between the spawn and the
// open. Pass true for attach against an already running daemon so historic
// log content is not replayed.
[[nodiscard]] fn attach_and_supervise(pid_t monitor_pid, u64 monitor_start_time,
                                      pid_t proxy_pid, u64 proxy_start_time,
                                      linux_namespace &ns,
                                      network_configurator &netconf, subnet sn,
                                      passwd &pw, bool tail_from_end)
    -> error_or<ok>;

} // namespace oo
