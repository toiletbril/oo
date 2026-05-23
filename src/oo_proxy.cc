#include "oo_proxy.hh"

#include "debug.hh"
#include "linux_util.hh"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>

namespace oo {

namespace {

// Upper bound on the request head we buffer before a client must have sent the
// terminating blank line. A client that never sends it cannot make the proxy
// grow this buffer without limit.
constexpr usize MAX_HEAD_BYTES = 65536;
constexpr usize RELAY_BUF_BYTES = 16384;

// How often the idle accept loop wakes to check that the namespace daemon is
// still alive.
constexpr int WATCH_TIMEOUT_MS = 2000;

// Accept only clients inside the oo address range 10.0.0.0/16. The host reaches
// the namespace proxy over the veth with a source in this range, so this keeps
// the proxy from relaying for peers on any other interface it might be bound
// to. It mirrors the squid backend's `acl src 10.0.0.0/16`.
fn client_allowed(const struct sockaddr_in &peer) -> bool {
  if (peer.sin_family != AF_INET) {
    return false;
  }
  const u32 addr = ntohl(peer.sin_addr.s_addr);
  return (addr & 0xFFFF0000u) == 0x0A000000u;
}

// True for an IPv4 127.0.0.0/8 or IPv6 ::1 destination. Refusing these stops
// the proxy from being used to reach services bound only to the namespace
// loopback.
fn is_loopback(const struct addrinfo *ai) -> bool {
  if (ai->ai_family == AF_INET) {
    const let *sin = reinterpret_cast<const struct sockaddr_in *>(ai->ai_addr);
    return (ntohl(sin->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
  }
  if (ai->ai_family == AF_INET6) {
    const let *sin6 =
        reinterpret_cast<const struct sockaddr_in6 *>(ai->ai_addr);
    return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) != 0;
  }
  return false;
}

// Split an authority into host and port, handling bracketed IPv6 literals such
// as "[2001:db8::1]:443". An unbracketed authority with more than one colon is
// treated as an IPv6 literal without a port. Returns false on a malformed value
// or an empty host.
fn split_host_port(const std::string &authority, std::string_view default_port,
                   std::string &host, std::string &port) -> bool {
  if (!authority.empty() && authority.front() == '[') {
    const let close = authority.find(']');
    if (close == std::string::npos) {
      return false;
    }
    host = authority.substr(1, close - 1);
    if (close + 1 == authority.size()) {
      port = std::string{default_port};
    } else if (authority[close + 1] == ':') {
      port = authority.substr(close + 2);
    } else {
      return false;
    }
  } else {
    const let first = authority.find(':');
    const let last = authority.rfind(':');
    if (first == std::string::npos) {
      host = authority;
      port = std::string{default_port};
    } else if (first != last) {
      host = authority;
      port = std::string{default_port};
    } else {
      host = authority.substr(0, last);
      port = authority.substr(last + 1);
    }
  }

  if (port.empty()) {
    port = std::string{default_port};
  }
  return !host.empty() && !port.empty();
}

fn write_all(int fd, std::string_view data) -> error_or<ok> {
  usize off = 0;
  while (off < data.size()) {
    let n = linux::oo_write(fd, data.data() + off, data.size() - off);
    if (n.is_err()) {
      return make_error("Proxy write to peer failed");
    }
    if (n.get_value() == 0) {
      return make_error("Proxy write to peer returned zero");
    }
    off += static_cast<usize>(n.get_value());
  }
  return ok{};
}

fn resolve_and_connect(const std::string &host, const std::string &port)
    -> error_or<linux::oo_fd> {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = nullptr;
  int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
  if (rc != 0) {
    return make_error("Could not resolve host '" + host +
                      "': " + std::string{gai_strerror(rc)});
  }

  linux::oo_fd out;
  bool saw_loopback = false;
  for (struct addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
    if (is_loopback(ai)) {
      saw_loopback = true;
      continue;
    }
    int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                      ai->ai_protocol);
    if (fd < 0) {
      continue;
    }
    linux::oo_fd candidate{fd};
    if (::connect(candidate, ai->ai_addr, ai->ai_addrlen) == 0) {
      out = std::move(candidate);
      break;
    }
  }
  ::freeaddrinfo(res);

  if (!out.is_valid()) {
    if (saw_loopback) {
      return make_error("Refusing to proxy to the loopback address '" + host +
                        "'");
    }
    return make_error("Could not connect to " + host + ":" + port);
  }
  return out;
}

// Relay bytes both ways until both directions have seen end of file. Each side
// is half-closed as soon as its peer stops sending so the other end learns the
// stream is finished.
fn pump_bidirectional(int a, int b) -> error_or<ok> {
  bool a_open = true;
  bool b_open = true;
  char buf[RELAY_BUF_BYTES];

  while (a_open || b_open) {
    struct pollfd fds[2];
    fds[0] = {.fd = a_open ? a : -1, .events = POLLIN, .revents = 0};
    fds[1] = {.fd = b_open ? b : -1, .events = POLLIN, .revents = 0};

    int ready = ::poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      return make_error("poll() failed in proxy tunnel: " +
                        linux::get_errno_string());
    }

    if (a_open && (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
      let n = linux::oo_read(a, buf, sizeof(buf));
      if (n.is_err() || n.get_value() == 0) {
        a_open = false;
        unused(::shutdown(b, SHUT_WR));
      } else if (write_all(b, std::string_view{buf, static_cast<usize>(
                                                        n.get_value())})
                     .is_err()) {
        a_open = false;
        b_open = false;
      }
    }

    if (b_open && (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
      let n = linux::oo_read(b, buf, sizeof(buf));
      if (n.is_err() || n.get_value() == 0) {
        b_open = false;
        unused(::shutdown(a, SHUT_WR));
      } else if (write_all(a, std::string_view{buf, static_cast<usize>(
                                                        n.get_value())})
                     .is_err()) {
        a_open = false;
        b_open = false;
      }
    }
  }

  return ok{};
}

} // namespace

fn oo_proxy::prepare(const endpoint &bind) -> error_or<ok> {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return make_error("Could not create proxy socket: " +
                      linux::get_errno_string());
  }
  linux::oo_fd listen_fd{fd};

  int one = 1;
  unused(::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(bind.port);
  if (inet_pton(AF_INET, bind.host.c_str(), &addr.sin_addr) != 1) {
    return make_error("The proxy bind host '" + bind.host + "' is not valid");
  }

  if (::bind(listen_fd, reinterpret_cast<struct sockaddr *>(&addr),
             sizeof(addr)) != 0) {
    return make_error("Could not bind proxy to '" + bind.to_string() +
                      "': " + linux::get_errno_string());
  }

  if (::listen(listen_fd, SOMAXCONN) != 0) {
    return make_error("Could not listen on '" + bind.to_string() +
                      "': " + linux::get_errno_string());
  }

  m_listen_fd = std::move(listen_fd);
  trace(verbosity::info, "Built-in proxy bound to {} for namespace '{}'",
        bind.to_string(), m_ns.get_name());

  return ok{};
}

fn oo_proxy::run() -> error_or<ok> {
  insist(m_listen_fd.is_valid(),
         "run() requires prepare() to have created the listener");

  // Auto-reap connection children so finished handlers do not become zombies.
  struct sigaction sa{};
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NOCLDWAIT;
  unused(::sigaction(SIGCHLD, &sa, nullptr));

  // A peer that closes mid-write must not take the whole proxy down.
  unused(::signal(SIGPIPE, SIG_IGN));

  for (;;) {
    struct pollfd pfd = {
        .fd = m_listen_fd.get(), .events = POLLIN, .revents = 0};
    int ready = ::poll(&pfd, 1, WATCH_TIMEOUT_MS);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      return make_error("poll() failed on proxy listener: " +
                        linux::get_errno_string());
    }

    if (ready == 0) {
      // Idle tick. Exit once the namespace daemon is gone so an orphaned proxy
      // does not keep the network namespace pinned.
      if (::kill(m_daemon_pid, 0) != 0 && errno == ESRCH) {
        trace(verbosity::info, "Daemon {} is gone; proxy exiting",
              m_daemon_pid);
        return ok{};
      }
      continue;
    }

    struct sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    int client = ::accept(
        m_listen_fd, reinterpret_cast<struct sockaddr *>(&peer), &peer_len);
    if (client < 0) {
      if (errno == EINTR || errno == ECONNABORTED) {
        continue;
      }
      return make_error("accept() failed: " + linux::get_errno_string());
    }

    linux::oo_fd client_fd{client};

    if (!client_allowed(peer)) {
      // Source outside the oo address range. Drop it; oo_fd closes the socket.
      continue;
    }

    let pid = linux::oo_fork();
    if (pid.is_err()) {
      // Drop this connection but keep serving the rest.
      continue;
    }

    if (pid.get_value() == 0) {
      let r = handle_client(std::move(client_fd));
      _exit(r.is_err() ? 1 : 0);
    }
  }
}

fn oo_proxy::handle_client(linux::oo_fd client) -> error_or<ok> {
  std::string head;
  char buf[RELAY_BUF_BYTES];
  usize header_end = std::string::npos;

  while (head.size() < MAX_HEAD_BYTES) {
    let n = linux::oo_read(client, buf, sizeof(buf));
    if (n.is_err()) {
      return make_error("Proxy read from client failed");
    }
    if (n.get_value() == 0) {
      // Client closed before sending a complete request.
      return ok{};
    }
    head.append(buf, static_cast<usize>(n.get_value()));
    header_end = head.find("\r\n\r\n");
    if (header_end != std::string::npos) {
      break;
    }
  }

  if (header_end == std::string::npos) {
    return make_error("Proxy request head is too large or incomplete");
  }

  let line_end = head.find("\r\n");
  insist(line_end != std::string::npos,
         "a head containing the blank line must contain a request line");
  const std::string request_line = head.substr(0, line_end);

  let sp1 = request_line.find(' ');
  let sp2 = request_line.rfind(' ');
  if (sp1 == std::string::npos || sp2 == std::string::npos || sp1 == sp2) {
    return make_error("The proxy request line '" + request_line +
                      "' is malformed");
  }

  const std::string method = request_line.substr(0, sp1);
  const std::string target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
  const std::string version = request_line.substr(sp2 + 1);

  if (method == "CONNECT") {
    std::string host;
    std::string port;
    if (!split_host_port(target, "", host, port)) {
      return make_error("The CONNECT target must be host:port, but got '" +
                        target + "'");
    }

    let upstream = unwrap(resolve_and_connect(host, port));
    unwrap(write_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n"));
    unwrap(pump_bidirectional(client, upstream));
    return ok{};
  }

  const std::string scheme = "http://";
  if (!target.starts_with(scheme)) {
    return make_error("The proxy supports CONNECT and absolute http:// targets "
                      "only, but got '" +
                      target + "'");
  }

  const std::string rest = target.substr(scheme.size());
  let slash = rest.find('/');
  const std::string authority =
      slash == std::string::npos ? rest : rest.substr(0, slash);
  const std::string path =
      slash == std::string::npos ? "/" : rest.substr(slash);

  std::string host;
  std::string port;
  if (!split_host_port(authority, "80", host, port)) {
    return make_error("The proxy request target '" + target +
                      "' is missing a host");
  }

  let upstream = unwrap(resolve_and_connect(host, port));

  // Rewrite the request line to origin form, then forward the original headers
  // and any buffered body bytes verbatim.
  std::string forwarded = method + " " + path + " " + version + "\r\n";
  forwarded += head.substr(line_end + 2);
  unwrap(write_all(upstream, forwarded));

  unwrap(pump_bidirectional(client, upstream));
  return ok{};
}

} // namespace oo
