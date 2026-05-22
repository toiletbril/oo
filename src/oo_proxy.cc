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
    return make_error("Could not resolve " + host + ": " +
                      std::string{gai_strerror(rc)});
  }

  linux::oo_fd out;
  for (struct addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
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
    return make_error("Invalid proxy bind host: " + bind.host);
  }

  if (::bind(listen_fd, reinterpret_cast<struct sockaddr *>(&addr),
             sizeof(addr)) != 0) {
    return make_error("Could not bind proxy to " + bind.to_string() + ": " +
                      linux::get_errno_string());
  }

  if (::listen(listen_fd, SOMAXCONN) != 0) {
    return make_error("Could not listen on " + bind.to_string() + ": " +
                      linux::get_errno_string());
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
    int client = ::accept(m_listen_fd, nullptr, nullptr);
    if (client < 0) {
      if (errno == EINTR || errno == ECONNABORTED) {
        continue;
      }
      return make_error("accept() failed: " + linux::get_errno_string());
    }

    linux::oo_fd client_fd{client};

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
    return make_error("Malformed proxy request line: " + request_line);
  }

  const std::string method = request_line.substr(0, sp1);
  const std::string target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
  const std::string version = request_line.substr(sp2 + 1);

  if (method == "CONNECT") {
    let colon = target.rfind(':');
    if (colon == std::string::npos) {
      return make_error("CONNECT target must be host:port: " + target);
    }
    const std::string host = target.substr(0, colon);
    const std::string port = target.substr(colon + 1);

    let upstream = unwrap(resolve_and_connect(host, port));
    unwrap(write_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n"));
    unwrap(pump_bidirectional(client, upstream));
    return ok{};
  }

  const std::string scheme = "http://";
  if (!target.starts_with(scheme)) {
    return make_error(
        "Proxy supports CONNECT and absolute http:// targets only: " + target);
  }

  const std::string rest = target.substr(scheme.size());
  let slash = rest.find('/');
  const std::string authority =
      slash == std::string::npos ? rest : rest.substr(0, slash);
  const std::string path =
      slash == std::string::npos ? "/" : rest.substr(slash);

  std::string host = authority;
  std::string port = "80";
  if (let colon = authority.rfind(':'); colon != std::string::npos) {
    host = authority.substr(0, colon);
    port = authority.substr(colon + 1);
  }
  if (host.empty()) {
    return make_error("Proxy request is missing a host: " + target);
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
