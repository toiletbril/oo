#include "privilege_drop.hh"

#include "debug.hh"
#include "linux_util.hh"
#include "oorunner.hh"

#include <grp.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

namespace oo {

namespace privilege_drop {

// Re-raise the effective set after a setresuid transition. KEEPCAPS retains
// the permitted set across uid changes, but the kernel still clears the
// effective set on any uid transition for a non-root process. We raise the
// same caps that the file caps granted.
static fn raise_effective_caps() -> error_or<ok>
{
  cap_t caps =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to get process capabilities"));
  insist(caps != nullptr,
         "cap_get_proc success must yield a non-null capability handle");
  defer { cap_free(caps); };

  // Copy all bits from the permitted set into the effective set. We do not
  // enumerate caps here because caps.cc owns the authoritative list and we
  // want raise_effective_caps to stay correct if that list changes.
  for (int cap = 0; cap <= CAP_LAST_CAP; ++cap) {
    cap_flag_value_t permitted = CAP_CLEAR;
    if (cap_get_flag(caps, cap, CAP_PERMITTED, &permitted) != 0) {
      continue;
    }
    if (permitted == CAP_SET) {
      cap_value_t one[] = {static_cast<cap_value_t>(cap)};
      unwrap(
          oo_linux_syscall(cap_set_flag, caps, CAP_EFFECTIVE, 1, one, CAP_SET));
    }
  }

  unwrap(oo_linux_syscall(cap_set_proc, caps));

  // SECURITY: verify every permitted cap is now actually effective. A
  // silent cap_set_proc no-op would leave the process running without the
  // caps it just pretended to raise.
  cap_t check =
      unwrap(oo_non_zero(cap_get_proc(), "Failed to re-read capabilities"));
  insist(check != nullptr,
         "cap_get_proc success must yield a non-null capability handle");
  defer { cap_free(check); };
  for (int cap = 0; cap <= CAP_LAST_CAP; ++cap) {
    cap_flag_value_t permitted = CAP_CLEAR;
    cap_flag_value_t effective = CAP_CLEAR;
    if (cap_get_flag(check, cap, CAP_PERMITTED, &permitted) != 0) continue;
    if (permitted != CAP_SET) continue;
    cap_get_flag(check, cap, CAP_EFFECTIVE, &effective);
    insist(effective == CAP_SET,
           "raise_effective_caps left a permitted cap non-effective");
  }
  return ok{};
}

fn switch_to_oorunner(uid_t *out_invoking_uid, gid_t *out_invoking_gid)
    -> error_or<ok>
{
  insist(out_invoking_uid != nullptr,
         "switch_to_oorunner requires an out uid pointer");
  insist(out_invoking_gid != nullptr,
         "switch_to_oorunner requires an out gid pointer");

  *out_invoking_uid = ::getuid();
  *out_invoking_gid = ::getgid();

  let cred = unwrap(oorunner::lookup());
  insist(cred.uid > 0 && cred.gid > 0,
         "oorunner account must not resolve to root. Fuck you");

  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
    return make_error("prctl(PR_SET_KEEPCAPS, 1) failed: " +
                      linux::get_errno_string());
  }
  defer { prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0); };

  // SECURITY: Clear supplementary groups before narrowing primary gid so the
  // process does not retain group memberships from the invoking user.
  unwrap(oo_linux_syscall(setgroups, (size_t) 1, &cred.gid));
  gid_t got_groups[2]{};
  int ngroups = ::getgroups(countof(got_groups), got_groups);
  insist(ngroups == 1 && got_groups[0] == cred.gid,
         "setgroups returned success but supplementary groups are not clean");

  unwrap(oo_linux_syscall(setresgid, cred.gid, cred.gid, cred.gid));
  gid_t rgid = 0, egid = 0, sgid = 0;
  unwrap(oo_linux_syscall(getresgid, &rgid, &egid, &sgid));
  insist(rgid == cred.gid && egid == cred.gid && sgid == cred.gid,
         "setresgid returned success but not all three gid slots match");

  unwrap(oo_linux_syscall(setresuid, cred.uid, cred.uid, cred.uid));
  uid_t ruid = 0, euid = 0, suid = 0;
  unwrap(oo_linux_syscall(getresuid, &ruid, &euid, &suid));
  insist(ruid == cred.uid && euid == cred.uid && suid == cred.uid,
         "setresuid returned success but not all three uid slots match");

  unwrap(raise_effective_caps());

  trace(verbosity::debug,
        "Switched to oorunner (uid={}, gid={}); invoking user was "
        "(uid={}, gid={})",
        cred.uid, cred.gid, *out_invoking_uid, *out_invoking_gid);
  return ok{};
}

fn switch_to_user(uid_t uid, gid_t gid) -> error_or<ok>
{
  // SECURITY: This call runs in forked children right before drop_for_exec
  // and execvp. No caps are preserved; the child inherits an empty ambient
  // set and drop_for_exec clears effective/inheritable.
  unwrap(oo_linux_syscall(setgroups, (size_t) 1, &gid));
  gid_t got_groups[2]{};
  int ngroups = ::getgroups(countof(got_groups), got_groups);
  insist(ngroups == 1 && got_groups[0] == gid,
         "setgroups returned success but supplementary groups are not clean");

  unwrap(oo_linux_syscall(setresgid, gid, gid, gid));
  gid_t rgid = 0, egid = 0, sgid = 0;
  unwrap(oo_linux_syscall(getresgid, &rgid, &egid, &sgid));
  insist(rgid == gid && egid == gid && sgid == gid,
         "setresgid returned success but not all three gid slots match");

  unwrap(oo_linux_syscall(setresuid, uid, uid, uid));
  uid_t ruid = 0, euid = 0, suid = 0;
  unwrap(oo_linux_syscall(getresuid, &ruid, &euid, &suid));
  insist(ruid == uid && euid == uid && suid == uid,
         "setresuid returned success but not all three uid slots match");

  trace(verbosity::debug, "Switched back to invoking user (uid={}, gid={})",
        uid, gid);
  return ok{};
}

} // namespace privilege_drop

} // namespace oo
