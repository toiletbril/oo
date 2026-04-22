#include "oorunner.hh"

#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <string>

namespace oo {

namespace oorunner {

namespace {

// RAII guards around the libc NSS iterator and the /etc/.pwd.lock advisory
// lock. Pair a set*/end* (or lck/ulck) call to the enclosing scope so they
// can never drift across early returns. Non-copyable, non-movable so the
// destructor fires exactly once at scope exit.

class nss_pwent_scope {
public:
  nss_pwent_scope() { ::setpwent(); }
  ~nss_pwent_scope() { ::endpwent(); }
  nss_pwent_scope(const nss_pwent_scope &) = delete;
  nss_pwent_scope &operator=(const nss_pwent_scope &) = delete;
  nss_pwent_scope(nss_pwent_scope &&) = delete;
  nss_pwent_scope &operator=(nss_pwent_scope &&) = delete;
};

class nss_grent_scope {
public:
  nss_grent_scope() { ::setgrent(); }
  ~nss_grent_scope() { ::endgrent(); }
  nss_grent_scope(const nss_grent_scope &) = delete;
  nss_grent_scope &operator=(const nss_grent_scope &) = delete;
  nss_grent_scope(nss_grent_scope &&) = delete;
  nss_grent_scope &operator=(nss_grent_scope &&) = delete;
};

// SECURITY: Serialize account edits against useradd/groupadd/passwd via
// the advisory lock on /etc/.pwd.lock. Best-effort: older systems ignore
// this, but glibc always provides it. Ctor logs the acquire failure and
// continues (the old code behaved this way); dtor always unlocks.
class pwd_lock_scope {
public:
  pwd_lock_scope() {
    if (::lckpwdf() != 0) {
      trace(verbosity::error, "lckpwdf() failed: {}",
            linux::get_errno_string());
    }
  }
  ~pwd_lock_scope() { ::ulckpwdf(); }
  pwd_lock_scope(const pwd_lock_scope &) = delete;
  pwd_lock_scope &operator=(const pwd_lock_scope &) = delete;
  pwd_lock_scope(pwd_lock_scope &&) = delete;
  pwd_lock_scope &operator=(pwd_lock_scope &&) = delete;
};

} // namespace

fn lookup() -> error_or<credentials> {
  errno = 0;
  struct passwd *pw = ::getpwnam(std::string{constants::OORUNNER_NAME}.c_str());
  if (pw == nullptr) {
    if (errno != 0) {
      return make_error("`getpwnam(oorunner)` failed: " +
                        linux::get_errno_string());
    }
    return make_error(
        "'oorunner' account does not exist. Run 'sudo oo init' first.");
  }
  return credentials{pw->pw_uid, pw->pw_gid};
}

// SECURITY: Pick the first unused uid in the system range [100, 999] by
// scanning /etc/passwd and /etc/group via libc. We search from the top
// down (999..100) so the chosen uid is least likely to collide with a
// future distro-managed system account, which distros conventionally
// allocate upward from SYS_UID_MIN.
static fn pick_system_uid() -> error_or<uid_t> {
  constexpr uid_t SYSTEM_UID_MIN = 100;
  constexpr uid_t SYSTEM_UID_MAX = 999;
  constexpr usize RANGE_SIZE = SYSTEM_UID_MAX - SYSTEM_UID_MIN + 1;

  std::array<bool, RANGE_SIZE> taken{};

  {
    nss_pwent_scope pwent;
    errno = 0;
    while (struct passwd *pw = ::getpwent()) {
      if (pw->pw_uid >= SYSTEM_UID_MIN && pw->pw_uid <= SYSTEM_UID_MAX) {
        taken[pw->pw_uid - SYSTEM_UID_MIN] = true;
      }
      errno = 0;
    }
    if (errno != 0) {
      return make_error("`getpwent` failed: " + linux::get_errno_string());
    }
  }

  {
    nss_grent_scope grent;
    errno = 0;
    while (struct group *gr = ::getgrent()) {
      if (gr->gr_gid >= SYSTEM_UID_MIN && gr->gr_gid <= SYSTEM_UID_MAX) {
        taken[gr->gr_gid - SYSTEM_UID_MIN] = true;
      }
      errno = 0;
    }
    if (errno != 0) {
      return make_error("`getgrent` failed: " + linux::get_errno_string());
    }
  }

  for (usize i = RANGE_SIZE; i-- > 0;) {
    if (!taken[i]) {
      return static_cast<uid_t>(SYSTEM_UID_MIN + i);
    }
  }

  return make_error(
      "Could not pick a system uid: range [100, 999] is exhausted.");
}

static fn append_group(uid_t gid) -> error_or<ok> {
  FILE *f = ::fopen("/etc/group", "a");
  if (f == nullptr) {
    return make_error(std::string{"Failed to open /etc/group: "} +
                      linux::get_errno_string());
  }
  defer { ::fclose(f); };

  std::string name{constants::OORUNNER_NAME};
  char *members[] = {nullptr};
  char passwd[] = "x";
  struct group gr{};
  gr.gr_name = name.data();
  gr.gr_passwd = passwd;
  gr.gr_gid = gid;
  gr.gr_mem = members;

  if (::putgrent(&gr, f) != 0) {
    return make_error(std::string{"Failed to write /etc/group: "} +
                      linux::get_errno_string());
  }
  return ok{};
}

static fn append_passwd(uid_t uid, gid_t gid) -> error_or<ok> {
  FILE *f = ::fopen("/etc/passwd", "a");
  if (f == nullptr) {
    return make_error(std::string{"Failed to open /etc/passwd: "} +
                      linux::get_errno_string());
  }
  defer { ::fclose(f); };

  std::string name{constants::OORUNNER_NAME};
  std::string gecos{constants::OORUNNER_GECOS};
  std::string home{constants::OORUNNER_HOME};
  std::string shell{constants::OORUNNER_SHELL};
  char passwd[] = "x";
  struct passwd pw{};
  pw.pw_name = name.data();
  pw.pw_passwd = passwd;
  pw.pw_uid = uid;
  pw.pw_gid = gid;
  pw.pw_gecos = gecos.data();
  pw.pw_dir = home.data();
  pw.pw_shell = shell.data();

  if (::putpwent(&pw, f) != 0) {
    return make_error(std::string{"Failed to write /etc/passwd: "} +
                      linux::get_errno_string());
  }
  return ok{};
}

static fn append_shadow() -> error_or<ok> {
  std::error_code ec;
  if (!std::filesystem::exists("/etc/shadow", ec)) {
    trace(verbosity::info, "/etc/shadow not present; skipping shadow entry");
    return ok{};
  }

  FILE *f = ::fopen("/etc/shadow", "a");
  if (f == nullptr) {
    return make_error(std::string{"Failed to open /etc/shadow: "} +
                      linux::get_errno_string());
  }
  defer { ::fclose(f); };

  std::string name{constants::OORUNNER_NAME};
  char locked[] = "!*";
  struct spwd sp{};
  sp.sp_namp = name.data();
  sp.sp_pwdp = locked;
  sp.sp_lstchg = -1;
  sp.sp_min = -1;
  sp.sp_max = -1;
  sp.sp_warn = -1;
  sp.sp_inact = -1;
  sp.sp_expire = -1;
  sp.sp_flag = static_cast<unsigned long>(-1);

  if (::putspent(&sp, f) != 0) {
    return make_error(std::string{"Failed to write /etc/shadow: "} +
                      linux::get_errno_string());
  }
  return ok{};
}

fn ensure_exists() -> error_or<ok> {
  errno = 0;
  if (::getpwnam(std::string{constants::OORUNNER_NAME}.c_str()) != nullptr) {
    trace(verbosity::info, "'{}' account already exists",
          constants::OORUNNER_NAME);
    return ok{};
  }
  if (errno != 0 && errno != ENOENT && errno != ESRCH && errno != EBADF &&
      errno != EPERM) {
    return make_error("`getpwnam(oorunner)` failed: " +
                      linux::get_errno_string());
  }

  let uid = unwrap(pick_system_uid());
  insist(uid >= 100 && uid <= 999,
         "pick_system_uid must return a value in the system uid range");
  let gid = static_cast<gid_t>(uid);

  {
    pwd_lock_scope pwd_lock;
    unwrap(append_group(gid));
    unwrap(append_passwd(uid, gid));
    unwrap(append_shadow());
  }

  // SECURITY: drop any cached libc NSS state from the earlier
  // pick_system_uid() scan and the initial getpwnam(oorunner) negative
  // lookup. Without this, the next getpwnam() in this same process (from
  // lookup() in init) returns the stale "not found" and misreports the
  // freshly-created account as missing. Re-check the name resolves before
  // returning so the failure mode is diagnosable rather than surfacing
  // later as "account does not exist".
  ::endpwent();
  ::endgrent();

  errno = 0;
  if (::getpwnam(std::string{constants::OORUNNER_NAME}.c_str()) == nullptr) {
    return make_error(
        "Created '" + std::string{constants::OORUNNER_NAME} +
        "' but getpwnam still does not resolve it after NSS refresh" +
        (errno != 0 ? ": " + linux::get_errno_string() : std::string{}));
  }

  trace(verbosity::info, "Created '{}' system account (uid={}, gid={})",
        constants::OORUNNER_NAME, uid, gid);

  return ok{};
}

} // namespace oorunner

} // namespace oo
