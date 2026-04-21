#pragma once

#include "common.hh"
#include "error.hh"

#include <sys/types.h>

namespace oo {

namespace oorunner {

struct credentials
{
  uid_t uid;
  gid_t gid;
};

// Look up the oorunner account in /etc/passwd via libc. Returns the uid/gid
// of the account or an error if it does not exist.
[[nodiscard]] fn lookup() -> error_or<credentials>;

// Create the oorunner account if it does not already exist. Must be called
// while running as root (init only). Appends entries to /etc/passwd,
// /etc/group, and /etc/shadow (shadow is skipped if it does not exist).
// The password is locked with "!*" and the shell is set to nologin.
[[nodiscard]] fn ensure_exists() -> error_or<ok>;

} // namespace oorunner

} // namespace oo
