#include "oorunner.hh"

#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

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

fn lookup() -> error_or<credentials>
{
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

// SECURITY: We walk /etc/passwd via getpwent and pick the next free uid in
// the system range [100, 999]. This is conservative; distros vary (some
// systems reserve up to 499 or 999). If the range is exhausted we bail
// rather than stepping on a regular user.
static fn pick_system_uid() -> error_or<uid_t>
{
  constexpr uid_t SYSTEM_UID_MIN = 100;
  constexpr uid_t SYSTEM_UID_MAX = 999;

  uid_t highest = SYSTEM_UID_MIN - 1;

  ::setpwent();
  defer { ::endpwent(); };

  errno = 0;
  while (struct passwd *pw = ::getpwent()) {
    if (pw->pw_uid >= SYSTEM_UID_MIN && pw->pw_uid <= SYSTEM_UID_MAX &&
        pw->pw_uid > highest)
    {
      highest = pw->pw_uid;
    }
    errno = 0;
  }
  if (errno != 0) {
    return make_error("`getpwent` failed: " + linux::get_errno_string());
  }

  if (highest >= SYSTEM_UID_MAX) {
    return make_error(
        "Could not pick a system uid: range [100, 999] is exhausted.");
  }

  return static_cast<uid_t>(highest + 1);
}

static fn append_group(uid_t gid) -> error_or<ok>
{
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

static fn append_passwd(uid_t uid, gid_t gid) -> error_or<ok>
{
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

static fn append_shadow() -> error_or<ok>
{
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

fn ensure_exists() -> error_or<ok>
{
  errno = 0;
  if (::getpwnam(std::string{constants::OORUNNER_NAME}.c_str()) != nullptr) {
    trace(verbosity::info, "'{}' account already exists",
          constants::OORUNNER_NAME);
    return ok{};
  }
  if (errno != 0 && errno != ENOENT && errno != ESRCH && errno != EBADF &&
      errno != EPERM)
  {
    return make_error("`getpwnam(oorunner)` failed: " +
                      linux::get_errno_string());
  }

  let uid = unwrap(pick_system_uid());
  let gid = static_cast<gid_t>(uid);

  // SECURITY: Serialize account edits against useradd/groupadd/passwd via
  // the advisory lock on /etc/.pwd.lock. Best-effort: older systems ignore
  // this, but glibc always provides it.
  if (::lckpwdf() != 0) {
    trace(verbosity::error, "lckpwdf() failed: {}", linux::get_errno_string());
  }
  defer { ::ulckpwdf(); };

  unwrap(append_group(gid));
  unwrap(append_passwd(uid, gid));
  unwrap(append_shadow());

  trace(verbosity::info, "Created '{}' system account (uid={}, gid={})",
        constants::OORUNNER_NAME, uid, gid);

  return ok{};
}

} // namespace oorunner

} // namespace oo
