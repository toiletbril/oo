#include "privilege_drop.hh"

#include "debug.hh"
#include "linux_util.hh"
#include "oorunner.hh"

#include <grp.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

namespace oo {

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

fn passwd::su_oorunner() -> error_or<ok>
{
  insist(!m_captured,
         "passwd::su_oorunner must be called at most once per instance");

  m_invoking_uid = ::getuid();
  m_invoking_gid = ::getgid();

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

  m_captured = true;

  trace(verbosity::debug,
        "Switched to oorunner (uid={}, gid={}); invoking user was "
        "(uid={}, gid={})",
        cred.uid, cred.gid, m_invoking_uid, m_invoking_gid);
  return ok{};
}

fn passwd::su() const -> error_or<ok>
{
  // SECURITY: This call runs in forked children right before drop_for_exec
  // and execvp. No caps are preserved; the child inherits an empty ambient
  // set and drop_for_exec clears effective/inheritable.
  insist(m_captured,
         "passwd::su called before su_oorunner captured invoking credentials");

  unwrap(oo_linux_syscall(setgroups, (size_t) 1, &m_invoking_gid));
  gid_t got_groups[2]{};
  int ngroups = ::getgroups(countof(got_groups), got_groups);
  insist(ngroups == 1 && got_groups[0] == m_invoking_gid,
         "setgroups returned success but supplementary groups are not clean");

  unwrap(oo_linux_syscall(setresgid, m_invoking_gid, m_invoking_gid,
                          m_invoking_gid));
  gid_t rgid = 0, egid = 0, sgid = 0;
  unwrap(oo_linux_syscall(getresgid, &rgid, &egid, &sgid));
  insist(rgid == m_invoking_gid && egid == m_invoking_gid &&
             sgid == m_invoking_gid,
         "setresgid returned success but not all three gid slots match");

  unwrap(oo_linux_syscall(setresuid, m_invoking_uid, m_invoking_uid,
                          m_invoking_uid));
  uid_t ruid = 0, euid = 0, suid = 0;
  unwrap(oo_linux_syscall(getresuid, &ruid, &euid, &suid));
  insist(ruid == m_invoking_uid && euid == m_invoking_uid &&
             suid == m_invoking_uid,
         "setresuid returned success but not all three uid slots match");

  trace(verbosity::debug, "Switched back to invoking user (uid={}, gid={})",
        m_invoking_uid, m_invoking_gid);
  return ok{};
}

} // namespace oo
