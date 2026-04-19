#include "caps.hh"
#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "error.hh"
#include "linux_util.hh"

#include <sys/prctl.h>

namespace oo {

namespace caps {

static cap_value_t CAP_LIST[] = {
    // unshare(CLONE_NEWNET|CLONE_NEWNS)
    CAP_SYS_ADMIN,
    // netlink, routes, veth
    CAP_NET_ADMIN,
    // setns() to enter namespaces
    CAP_SYS_PTRACE,
    // UNSAFE: bypasses all DAC file permission checks;
    // needed so iptables children can open /run/xtables.lock
    CAP_DAC_OVERRIDE,
    // UNSAFE: allows arbitrary UID changes;
    // needed so iptables children can setuid(0) to pass its root check
    CAP_SETUID,
    // allows dropping caps in children
    CAP_SETPCAP,
};

fn raise_ambient_capabilities() -> error_or<ok> {
  cap_t caps =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to get process capabilities"));
  defer { cap_free(caps); };

  // PR_CAP_AMBIENT_RAISE requires the cap in both permitted and inheritable.
  // File caps only populate permitted; set inheritable explicitly first.
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE,
                          countof(CAP_LIST), CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_proc, caps));

  for (const cap_value_t cap : CAP_LIST) {
    int ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
    if (ret != 0) {
      return make_error(std::format("Failed to raise ambient capability {}: {}",
                                    cap, linux::get_errno_string()));
    }
  }
  trace(verbosity::debug, "Raised ambient capabilities");
  return ok{};
}

fn set_file_capabilities(const char *path) -> error_or<ok> {
  cap_t caps =
      unwrap(oo_non_zero(cap_init(), "Failed to initialize capability state"));
  defer { cap_free(caps); };

  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE, countof(CAP_LIST),
                          CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE,
                          countof(CAP_LIST), CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_PERMITTED, countof(CAP_LIST),
                          CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_file, path, caps));

  cap_t file_caps = cap_get_file(path);
  if (file_caps) {
    char *cap_text = cap_to_text(file_caps, nullptr);
    if (cap_text) {
      trace(verbosity::info, "Current capabilities: {}", cap_text);
      cap_free(cap_text);
    }
    cap_free(file_caps);
  }

  return ok{};
}

} // namespace caps

} // namespace oo
