#include "caps.hh"

#include "common.hh"
#include "constants.hh"
#include "debug.hh"
#include "error.hh"
#include "linux_util.hh"

#include <cstdarg>
#include <string>
#include <sys/prctl.h>
#include <vector>

namespace oo {

namespace caps {

// SECURITY: These capabilities are held by the oo binary via file capabilities
// (set by `oo init`). They are used ONLY by the oo process itself for its own
// syscalls. The ambient set is never raised, so exec'd children (daemon, exec
// target, iptables) inherit NONE of these capabilities unless a caller uses
// drop_all_caps_except() to preserve a specific one via the ambient set. Call
// drop_all_caps() (or drop_all_caps_except) in every child process before
// execvp.
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

fn set_file_capabilities(const char *path) -> error_or<ok> {
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

static fn check_caps_are_in_list() -> error_or<ok> {
  cap_t check =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to re-read dropped caps"));
  insist(check != nullptr,
         "cap_get_proc() success must yield a non-null capability handle");
  defer { cap_free(check); };
  for (let cap : CAP_LIST) {
    cap_flag_value_t effective = CAP_SET;
    cap_flag_value_t inheritable = CAP_SET;
    cap_get_flag(check, cap, CAP_EFFECTIVE, &effective);
    cap_get_flag(check, cap, CAP_INHERITABLE, &inheritable);
    insist(effective == CAP_CLEAR && inheritable == CAP_CLEAR,
           "drop_all_caps left effective or inheritable caps set");
  }
  return ok{};
}

fn drop_all_caps() -> error_or<ok> {
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
  unwrap(check_caps_are_in_list());

  trace(verbosity::info, "Dropped effective and inheritable caps for exec");

  return ok{};
}

fn drop_all_caps_except_impl(cap_value_t first, ...) -> error_or<ok> {
  // The public macro drop_all_caps_except(cap, ...) appends a trailing 0
  // sentinel, which terminates this loop. `first` absorbs the variadic
  // requirement that at least one argument is named; if a caller
  // accidentally writes drop_all_caps_except() the macro expands to
  // drop_all_caps_except_impl(, 0) and fails at compile time, which is
  // what we want.
  std::vector<cap_value_t> keep_list;
  if (first == 0) {
    return make_error("drop_all_caps_except requires at least one cap to keep");
  }
  keep_list.push_back(first);

  va_list args;
  va_start(args, first);
  for (;;) {
    // cap_value_t is `int`; va_arg must read the promoted type.
    const int next = va_arg(args, int);
    if (next == 0)
      break;
    keep_list.push_back(static_cast<cap_value_t>(next));
  }
  va_end(args);

  // SECURITY: reject caps the binary is not entitled to, so a future caller
  // cannot silently request CAP_DAC_OVERRIDE or similar and end up with a
  // no-op on the kept set while the rest of the code assumes the cap is
  // live.
  for (let keep : keep_list) {
    bool in_list = false;
    for (let cap : CAP_LIST) {
      if (cap == keep) {
        in_list = true;
        break;
      }
    }
    if (!in_list) {
      return make_error(
          "drop_all_caps_except() called with a capability outside CAP_LIST");
    }
  }

  // Start from a clean ambient set so we only raise what was requested.
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
    return make_error("Failed to clear ambient capabilities: " +
                      linux::get_errno_string());
  }

  cap_t caps =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to get process capabilities"));
  insist(caps != nullptr,
         "cap_get_proc() success must yield a non-null capability handle");
  defer { cap_free(caps); };

  // Clear every cap in CAP_LIST from effective and inheritable, then re-add
  // the kept ones. Operating on CAP_LIST rather than cap_clear_flag(ALL)
  // keeps the authoritative cap set local to caps.cc.
  for (let cap : CAP_LIST) {
    cap_value_t one[] = {cap};
    unwrap(
        oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE, 1, one, CAP_CLEAR));
    unwrap(oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE, 1, one,
                            CAP_CLEAR));
  }
  for (let keep : keep_list) {
    cap_value_t one[] = {keep};
    unwrap(
        oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE, 1, one, CAP_SET));
    unwrap(
        oo_linux_syscall(cap_set_flag, caps, CAP_INHERITABLE, 1, one, CAP_SET));
  }
  unwrap(oo_linux_syscall(cap_set_proc, caps));

  // SECURITY: raising ambient requires each cap to be present in both
  // permitted and inheritable. cap_set_proc above put the kept caps in
  // inheritable; file caps set by `oo init` put them in permitted. Without
  // this, the cap would not transition through execve into the exec'd
  // binary.
  for (let keep : keep_list) {
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, keep, 0, 0) != 0) {
      return make_error("Failed to raise ambient capability " +
                        std::to_string(keep) + ": " +
                        linux::get_errno_string());
    }
  }

  // SECURITY: last line of defense before execvp. Verify each kept cap is
  // set in effective/inheritable/ambient and every other cap in CAP_LIST is
  // clear in all three.
  cap_t check =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to re-read dropped caps"));
  insist(check != nullptr,
         "cap_get_proc success must yield a non-null capability handle");
  defer { cap_free(check); };
  for (let cap : CAP_LIST) {
    cap_flag_value_t effective = CAP_CLEAR;
    cap_flag_value_t inheritable = CAP_CLEAR;
    cap_get_flag(check, cap, CAP_EFFECTIVE, &effective);
    cap_get_flag(check, cap, CAP_INHERITABLE, &inheritable);
    const int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);

    bool is_keep = false;
    for (let keep : keep_list) {
      if (cap == keep) {
        is_keep = true;
        break;
      }
    }
    if (is_keep) {
      insist(effective == CAP_SET && inheritable == CAP_SET && ambient == 1,
             "drop_all_caps_except failed to keep a requested cap live");
    } else {
      insist(effective == CAP_CLEAR && inheritable == CAP_CLEAR && ambient == 0,
             "drop_all_caps_except left a non-kept cap set");
    }
  }

  std::string kept;
  for (usize i = 0; i < keep_list.size(); ++i) {
    if (i != 0)
      kept += ",";
    kept += std::to_string(keep_list[i]);
  }

  trace(verbosity::info,
        "Dropped all caps except {{{}}} (kept in eff/inh/ambient)", kept);

  return ok{};
}

} // namespace caps

} // namespace oo
