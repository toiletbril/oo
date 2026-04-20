#include "caps.hh"

#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "error.hh"
#include "linux_util.hh"

#include <sys/prctl.h>

namespace oo {

namespace caps {

// SECURITY: These capabilities are held by the oo binary via file capabilities
// (set by `oo init`). They are used ONLY by the oo process itself for its own
// syscalls. The ambient set is never raised, so exec'd children (daemon, exec
// target, iptables) inherit NONE of these capabilities. Call drop_for_exec()
// in every child process before execvp.
//
// The oo runtime drops to the `oorunner` system user before doing any work
// under /var/run/oo, so writes there are authorized by ordinary DAC -- NOT
// by a permission-bypass capability. CAP_DAC_OVERRIDE is intentionally
// absent. See privilege_drop.cc.
//
// Do not add capabilities to this list without a security review.
// Removing an entry breaks the feature that needs it:
//   CAP_SYS_ADMIN  -> unshare(CLONE_NEWNET|CLONE_NEWNS), setns()
//   CAP_NET_ADMIN  -> netlink, routes, veth pair creation
//   CAP_SYS_PTRACE -> setns() into another process's namespace
//   CAP_SETUID (UNSAFE) -> allows setuid(0) in forked iptables children and
//                    the initial switch to oorunner at runtime entry
//   CAP_SETGID     -> paired with CAP_SETUID for setresgid/setgroups on
//                    the oorunner transition and the drop back to the
//                    invoking user before exec
//   CAP_SYS_CHROOT -> setns(mnt_fd, CLONE_NEWNS)
static constexpr cap_value_t CAP_LIST[] = {
    CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE,
    CAP_SETUID,    CAP_SETGID,    CAP_SYS_CHROOT,
};

fn set_file_capabilities(const char *path) -> error_or<ok>
{
  cap_t caps =
      unwrap(oo_non_zero(cap_init(), "Failed to initialize capability state"));
  insist(caps != nullptr,
         "cap_init success must yield a non-null capability handle");
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

fn drop_for_exec() -> error_or<ok>
{
  // Clear the ambient set first (does not require any capability).
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
    return make_error("Failed to clear ambient capabilities: " +
                      linux::get_errno_string());
  }

  // Drop effective and inheritable sets so the exec'd binary inherits nothing
  // via the permitted = (inheritable & file_inheritable) | file_permitted path.
  // SECURITY: A process can always drop its own caps without special
  // privileges. If you add back CAP_EFFECTIVE or CAP_INHERITABLE here, the
  // exec'd child may acquire those caps from the kernel's capability transition
  // rules.
  cap_t caps =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to get process capabilities"));
  insist(caps != nullptr,
         "cap_get_proc success must yield a non-null capability handle");
  defer { cap_free(caps); };

  unwrap(oo_linux_syscall(cap_clear_flag, caps, CAP_EFFECTIVE));
  unwrap(oo_linux_syscall(cap_clear_flag, caps, CAP_INHERITABLE));
  unwrap(oo_linux_syscall(cap_set_proc, caps));

  // SECURITY: last line of defense before execvp. Re-read and assert every
  // cap we ever hold is now clear in both effective and inheritable sets.
  cap_t check =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to re-read dropped caps"));
  insist(check != nullptr,
         "cap_get_proc success must yield a non-null capability handle");
  defer { cap_free(check); };
  for (auto cap : CAP_LIST) {
    cap_flag_value_t effective = CAP_SET;
    cap_flag_value_t inheritable = CAP_SET;
    cap_get_flag(check, cap, CAP_EFFECTIVE, &effective);
    cap_get_flag(check, cap, CAP_INHERITABLE, &inheritable);
    insist(effective == CAP_CLEAR && inheritable == CAP_CLEAR,
           "drop_for_exec left effective or inheritable caps set");
  }

  trace(verbosity::debug, "Dropped effective and inheritable caps for exec");
  return ok{};
}

} // namespace caps

} // namespace oo
