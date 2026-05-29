# oo

[![Integration Tests](https://github.com/toiletbril/oo/actions/workflows/integration-tests.yml/badge.svg?branch=staging)](https://github.com/toiletbril/oo/actions/workflows/integration-tests.yml)

Run and proxy network daemons inside isolated Linux namespaces from the command
line via a small binary. Useful for split-tunneling TUN-based VPNs, or anything
else that benefits from a per-namespace routing table.

The software is very early stage. The security model is roughly 'I added as
many asserts as I could and there's probably only 3 users using this software'.

State lives under `/var/run/oo`. Each namespace gets its own subdirectory with
logs and persistent state files:

```
/var/run/oo/
├── ip-pool.ini          global subnet allocation state
└── <namespace>/
    ├── pids.ini         daemon and monitor PIDs
    ├── network.ini      subnet and veth interface names
    ├── resolv.conf      DNS config bind-mounted into the namespace
    ├── nsswitch.conf    nsswitch config bind-mounted into the namespace
    ├── stdout           daemon stdout
    └── stderr           daemon stderr
```

Building needs `clang` and `make`. There are no library dependencies. At
runtime, the only requirements are `iptables-legacy` and a recent Linux kernel
with network namespace support. To install:
```console
$ make
$ sudo make install
```

Before the first use, run once as root to set file capabilities on the binary
and create the runtime directory:
```console
$ sudo oo init
```

## Usage

Remember that running anything with `--help` prints a more detailed usage:
```console
$ oo [subcommand] --help
```

To start a daemon inside a fresh namespace:
```console
$ oo up vpn -- openvpn /etc/openvpn/client.conf
oo: Namespace `vpn` is up. Daemon PID is 1234.
oo: Daemon logs follow.
```

This creates a network namespace named `vpn`, sets up a `veth` pair with NAT
through the host's default interface, and launches the daemon inside it. The
daemon runs with its own private network stack. Its stdout and stderr are
written to `/var/run/oo/vpn/stdout` and `/var/run/oo/vpn/stderr`.

By default `oo up` stays attached, tails the daemon output to your terminal,
and tears the namespace down when the daemon exits. To detach and return to
the shell right away, pass `--background` (`-d`). The daemon then keeps running
until `oo down`:
```console
$ oo up vpn -d -- openvpn /etc/openvpn/client.conf
```

To use custom DNS, pass `--dns` (repeatable) or `--dns-file`, which
bind-mounts the given file as `/etc/resolv.conf` inside the namespace and
overrides `--dns` if both are given:
```console
$ oo up vpn --dns=1.1.1.1 --dns=8.8.8.8 -- openvpn /etc/openvpn/client.conf
$ oo up vpn --dns-file=/etc/resolv-vpn.conf -- openvpn /etc/openvpn/client.conf
```

To keep the daemon itself on the host's `/etc/resolv.conf` while still
applying the configured DNS to `oo exec` commands in the namespace, add
`--no-daemon-dns`:
```console
$ oo up vpn --dns=1.1.1.1 --no-daemon-dns -- openvpn /etc/openvpn/client.conf
```

To pick a non-default subnet prefix on the veth interface, use
`--subnet-prefix` with a value between 16 and 30 (default 30). Wider prefixes
overlap across namespaces; that is the caller's responsibility:
```console
$ oo up vpn --subnet-prefix=24 -- openvpn /etc/openvpn/client.conf
```

To reach the namespace's network from the host without entering it for every
command, start a forward proxy alongside the daemon with
`--http-proxy=<ip>:<port>`. The proxy binds inside the namespace, so it is
reachable from the host at the namespace IP. Every request it forwards resolves
through the namespace's DNS and leaves through the namespace's default route and
NAT:
```console
$ oo up vpn -d --http-proxy=0.0.0.0:8080 -- openvpn /etc/openvpn/client.conf
oo: Namespace `vpn` is up. Daemon PID is 1234.
oo: HTTP proxy is listening on 10.0.0.2:8080 with PID 1235.
$ curl -x 10.0.0.2:8080 https://example.com
```

The proxy serves plain HTTP through absolute-form requests and HTTPS through the
CONNECT method. It is open to any client that can reach the bind address, so
keep that address on a trusted interface.

To choose the proxy implementation, pass `--http-proxy-backend` with either
`builtin`, which is the default in-process proxy, or `squid`, which runs the
system squid and requires it to be installed:
```console
$ oo up vpn --http-proxy=0.0.0.0:8080 --http-proxy-backend=squid -- openvpn /etc/openvpn/client.conf
```

To run a command inside a running namespace, use `exec`. It exits with the
command's own exit code:
```console
$ oo exec vpn -- curl https://example.com
```

To see the state of every namespace, or of one in particular, use `status`:
```console
$ oo status
vpn: daemon is alive, proxy is alive, 10.0.0.2
$ oo status vpn
Namespace `vpn`
  Daemon PID:   1234 (alive)
  Proxy:        1235 (alive), builtin
  Host IP:      10.0.0.1
  Namespace IP: 10.0.0.2
```

To attach to or change a running namespace, use `touch`. With no flags it
attaches to the daemon and tails its output, the same way `oo up` does. The
flags let you manage the namespace without taking it down. Stop the proxy with
`--shutdown-proxy`, replace it with `--restart-proxy` together with a new
`--http-proxy`, or start one where there was none by passing `--http-proxy`
alone. Rebuild the network and respawn the daemon on the same subnet with
`--relaunch-daemon` and the daemon command after `--`, and rename the namespace
at the same time with `--set-name`:
```console
$ oo touch vpn
$ oo touch vpn --restart-proxy --http-proxy=0.0.0.0:8080
$ oo touch vpn --relaunch-daemon --set-name=work -- openvpn /etc/openvpn/work.conf
```

A relaunch stays attached and tails the new daemon like `oo up`. Pass
`--background` (`-d`) to detach instead.

To shut the daemon down and tear the namespace down:
```console
$ oo down vpn
```

`oo down` sends `SIGTERM` and waits up to ten seconds for a graceful exit
before falling back to `SIGKILL`, configurable with `--timeout=<seconds>`.

## Capabilities

`oo init` sets file capabilities on the binary so unprivileged users can
invoke namespace operations without `sudo`:

| Capability                 | Reason                                               |
|----------------------------|------------------------------------------------------|
| `CAP_SYS_ADMIN`            | `unshare()`, `setns()`                               |
| `CAP_NET_ADMIN`            | netlink, routing, veth pair                          |
| `CAP_SYS_PTRACE`           | `setns()` into another process's namespace           |
| `CAP_SETUID`, `CAP_SETGID` | `setuid(0)` in iptables/nftables children            |
| `CAP_SYS_CHROOT`           | `setns(mnt_fd, CLONE_NEWNS)` for the mount namespace |

These capabilities are used only by the `oo` process itself. All exec'd
children (the daemon, `oo exec` targets, iptables children) have their
effective and inheritable capability sets dropped before `exec`.

Runtime directory layout and permissions:

```
/var/run/oo/        oorunner:oorunner 0755 (only oo can create entries)
/var/run/oo/<name>/ oorunner:oorunner 0700 (only creator can access)
```

## Development

`make test` runs the integration suite. The `MODE` variable controls the build
type:

| `MODE=` | Description                             |
|---------|-----------------------------------------|
| `dbg`   | Debug build (default)                   |
| `asan`  | Debug build with AddressSanitizer       |
| `rel`   | Release build                           |
| `prof`  | Release build with debug symbols        |

```console
$ make MODE=rel
$ make MODE=asan test
```

Run `make fmt` before committing.

Happy tunneling.
