#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/types.h>

namespace oo {

namespace privilege_drop {

// Before dispatching any runtime subcommand, switch the process to the
// oorunner system user while preserving the file capabilities loaded from
// the binary. The invoking user's uid/gid are written through the out
// pointers so child processes can drop back to them before exec.
//
// SECURITY: This is the runtime permission-model invariant. The parent
// writes to /var/run/oo as oorunner (normal DAC), never via
// CAP_DAC_OVERRIDE. Capabilities survive via PR_SET_KEEPCAPS and are
// re-raised into the effective set after setresuid.
fn switch_to_oorunner(uid_t *out_invoking_uid, gid_t *out_invoking_gid)
    -> error_or<ok>;

// In a forked child, drop back to the invoking user before `drop_for_exec`
// and `execvp`. The target uid/gid come from `switch_to_oorunner`'s output.
// No capabilities are preserved; the caller is expected to have already
// dropped them or to do so immediately.
fn switch_to_user(uid_t uid, gid_t gid) -> error_or<ok>;

} // namespace privilege_drop

} // namespace oo
