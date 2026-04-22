#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/types.h>

namespace oo {

// Owns the uid/gid pair the process was launched under and the setuid
// transitions into and out of the oorunner service account. One instance
// per subcommand invocation: su_oorunner() captures the invoking
// credentials into members, then forked children call su() to drop back
// to them before drop_all_caps() and execvp().
//
// SECURITY: This is the runtime permission-model invariant. The parent
// writes to /var/run/oo as oorunner (normal DAC), never via
// CAP_DAC_OVERRIDE. Capabilities survive su_oorunner() via
// PR_SET_KEEPCAPS and are re-raised into the effective set after
// setresuid. su() preserves no caps; the caller must run drop_for_exec
// (drop_all_caps / drop_all_caps_except) itself immediately after.
class passwd {
public:
  passwd() = default;

  passwd(const passwd &) = delete;
  passwd &operator=(const passwd &) = delete;

  [[nodiscard]] fn su_oorunner() -> error_or<ok>;
  [[nodiscard]] fn su() const -> error_or<ok>;

  [[nodiscard]] fn get_invoking_uid() const -> uid_t { return m_invoking_uid; }
  [[nodiscard]] fn get_invoking_gid() const -> gid_t { return m_invoking_gid; }

private:
  uid_t m_invoking_uid{0};
  gid_t m_invoking_gid{0};
  bool m_captured{false};
};

} // namespace oo
