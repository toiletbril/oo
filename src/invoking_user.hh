#pragma once

#include <sys/types.h>

namespace oo {

// Invoking user's uid/gid captured before the process switches to oorunner.
// Set exactly once in oo.cc before dispatching a runtime subcommand and
// read by the exec paths in satan.cc so they can drop back to this user
// before the final execvp.
//
// SECURITY: If this is read before it has been set (e.g. from a new code
// path added outside the subcommand dispatcher), child processes would
// exec as uid=0-of-oorunner. Tests assert the uid matches the invoking
// user to catch that regression.
extern uid_t g_invoking_uid;
extern gid_t g_invoking_gid;

} // namespace oo
