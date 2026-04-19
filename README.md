# oo

Run daemons inside isolated Linux network namespaces from the command line.
Allows, for example, split-tunnel anything for TUN-based VPNs, based on
namespace they were launched in.

State is kept under `/var/run/oo`. Each namespace gets its own subdirectory
with daemon logs and persistent state files:

```
/var/run/oo/
├── ip-pool.ini          global subnet allocation state
└── <namespace>/
    ├── pids.ini         daemon and monitor PIDs
    ├── network.ini      subnet and veth interface names
    ├── resolv.conf      DNS config bind-mounted into the namespace
    ├── nsswitch.conf    nsswitch config bind-mounted into the namespace
    ├── stdout           daemon stdout (append)
    └── stderr           daemon stderr (append)
```

Before the first use, run once as root to set file capabilities on the binary
and create the runtime directory:
```console
$ sudo oo init
```

To build from source, you need `clang` and `make`. There are no library
dependencies. At runtime, the only requirement is `iptables-legacy` and a
recent Linux kernel with network namespace support. Then:
```console
$ make
$ make install
```

## Usage

Running any subcommand with `--help` prints a more detailed usage:
```console
$ oo [subcommand] --help
```

To start a daemon inside a new namespace:
```console
$ oo up vpn -- openvpn /etc/openvpn/client.conf
oo: Namespace `vpn` is up. Daemon PID: 1234.
```

This creates a network namespace named `vpn`, sets up a `veth` pair with NAT
through the host's default interface, and starts the daemon inside it. The
daemon runs with its own private network stack. Its stdout and stderr are
written to `/var/run/oo/vpn/stdout` and `/var/run/oo/vpn/stderr`.

To use custom DNS inside the namespace, pass `--dns` or `--dns-file`:
```console
$ oo up vpn --dns=1.1.1.1 --dns=8.8.8.8 -- openvpn /etc/openvpn/client.conf
$ oo up vpn --dns-file=/etc/resolv-vpn.conf -- openvpn /etc/openvpn/client.conf
```

`--dns` can be specified multiple times. `--dns-file` bind-mounts the given
file as `/etc/resolv.conf` inside the namespace and overrides `--dns` if both
are provided.

To run a command inside a running namespace:
```console
$ oo exec vpn -- curl https://example.com
```

The command runs inside the `vpn` namespace, subject to its routing table and
DNS. It exits with the command's exit code.

To shut the daemon down and tear the namespace down:
```console
$ oo down vpn
```

`oo down` sends `SIGTERM` to the daemon and waits up to ten seconds for a
graceful exit before falling back to `SIGKILL`. The timeout is configurable
with `--timeout=<seconds>`.

## Security

This is pre-production software. It has not been audited and is not suitable
for shared or multi-tenant systems. The security model assumes a small group
of trusted users on a single machine.

After `oo init`, the binary holds the following Linux file capabilities:

| Capability | Risk | Reason |
|---|---|---|
| `CAP_SYS_ADMIN` | Medium | `unshare(CLONE_NEWNET\|CLONE_NEWNS)`, `setns()` |
| `CAP_NET_ADMIN` | Low | netlink, routing, veth pair creation |
| `CAP_SYS_PTRACE` | Low | `setns()` into another process's namespace |
| `CAP_DAC_OVERRIDE` | **High** | **Bypasses all filesystem permission checks**; needed to create dirs in `/var/run/oo` and so iptables children can open `/run/xtables.lock` after `setuid(0)` |
| `CAP_SETUID` | **High** | **Allows `setuid(0)` in child processes**; needed so iptables/nftables can pass their internal root check |
| `CAP_SYS_CHROOT` | Medium | `setns(mnt_fd, CLONE_NEWNS)` for mount namespace |
| `CAP_SETPCAP` | Low | Modify capability bounding set in children |

These capabilities are used only by the `oo` process itself. All exec'd child
processes (the daemon, `oo exec` targets, and iptables children) have their
effective and inheritable capability sets dropped before `execvp`.

The runtime directory layout and permissions:

```
/var/run/oo/          root:root  0755  (only oo can create entries)
/var/run/oo/<name>/   user:user  0700  (only creator can access)
```

Any user who can invoke `oo up` can start processes that run with namespace
isolation. Do not grant access to `oo` on machines with untrusted users.

## Development

Build and run tests with:
```console
$ make
$ make test
```

The `MODE` variable controls the build type:

| `MODE=` | Description |
|---------|-------------|
| `dbg`   | Debug build, no optimizations (default) |
| `asan`  | AddressSanitizer enabled |
| `rel`   | Release build, optimized |
| `prof`  | Profiling build |

```console
$ make MODE=rel
$ make MODE=asan test
```

Run the formatter before committing:
```console
$ make fmt
```
