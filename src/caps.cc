#include "caps.hh"
#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <sys/prctl.h>

namespace oo {

namespace caps {


static cap_value_t CAP_LIST[] = {CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE,
                                  CAP_SETPCAP};

fn raise_ambient_capabilities() -> void {
  for (const cap_value_t cap : CAP_LIST) {
    int ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
    if (ret != 0) {
      trace(verbosity::warn, "Failed to raise ambient capability {}: {}", cap,
            linux::get_errno_string());
    }
  }
  trace(verbosity::debug, "Raised ambient capabilities");
}

fn set_file_capabilities(const char *path) -> error_or<ok> {
  cap_t caps =
      unwrap(oo_non_zero(cap_init(), "Failed to initialize capability state"));
  defer { cap_free(caps); };

  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE,
                          countof(CAP_LIST), CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE,
                          countof(CAP_LIST), CAP_LIST, CAP_SET));
  unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_PERMITTED,
                          countof(CAP_LIST), CAP_LIST, CAP_SET));
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
