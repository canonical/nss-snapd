// SPDX-FileCopyrightText: 2026 Zygmunt Krynicki
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <nss.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct snap_identity {
  uid_t uid;
  const char *name;
  size_t name_len;
};

/* Write errnop only when caller provided a pointer. */
static void set_error(int *errnop, int value) {
  if (errnop != NULL) {
    *errnop = value;
  }
}

/*
 * Parse SNAP_USER in the strict "uid:name" format.
 *
 * The module deliberately returns NOTFOUND for missing or malformed data so NSS
 * can continue querying the next configured provider.
 */
static enum nss_status parse_snap_user(struct snap_identity *identity,
                                       int *errnop) {
  const char *value = getenv("SNAP_USER");
  const char *colon;
  char *end = NULL;
  uintmax_t parsed_uid;
  const uintmax_t max_uid = (uintmax_t)((uid_t)-1);

  if (value == NULL || value[0] == '\0') {
    set_error(errnop, ENOENT);
    return NSS_STATUS_NOTFOUND;
  }

  /* Require exactly one ':' and non-empty uid/name parts. */
  colon = strchr(value, ':');
  if (colon == NULL || colon == value || colon[1] == '\0' ||
      strchr(colon + 1, ':') != NULL) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_NOTFOUND;
  }

  errno = 0;
  parsed_uid = strtoumax(value, &end, 10);
  /* UID must be numeric and fit in uid_t on this platform. */
  if (errno != 0 || end != colon || parsed_uid > max_uid) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_NOTFOUND;
  }

  identity->uid = (uid_t)parsed_uid;
  identity->name = colon + 1;
  identity->name_len = strlen(identity->name);

  if (identity->name_len == 0U) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_NOTFOUND;
  }

  return NSS_STATUS_SUCCESS;
}

/*
 * Populate struct passwd using caller-provided storage.
 *
 * NSS APIs require all output strings to live in the supplied buffer. This
 * function packs strings sequentially and points passwd fields into that
 * buffer.
 */
static enum nss_status fill_passwd(const struct snap_identity *identity,
                                   struct passwd *pwd, char *buffer,
                                   size_t buflen, int *errnop) {
  static const char passwd_value[] = "x";
  static const char gecos_value[] = "";
  static const char fallback_home[] = "/nonexistent";
  static const char fallback_shell[] = "/bin/false";

  const char *home = getenv("SNAP_REAL_HOME");
  const char *shell = getenv("SHELL");

  size_t passwd_len = sizeof(passwd_value);
  size_t gecos_len = sizeof(gecos_value);
  size_t home_len;
  size_t shell_len;
  size_t required;
  char *cursor = buffer;

  /* Optional env vars have deterministic fallbacks in MVP mode. */
  if (home == NULL || home[0] == '\0') {
    home = fallback_home;
  }
  if (shell == NULL || shell[0] == '\0') {
    shell = fallback_shell;
  }

  home_len = strlen(home) + 1U;
  shell_len = strlen(shell) + 1U;

  required =
      (identity->name_len + 1U) + passwd_len + gecos_len + home_len + shell_len;
  if (required > buflen) {
    /* Signal the standard NSS retry path with a larger buffer. */
    set_error(errnop, ERANGE);
    return NSS_STATUS_TRYAGAIN;
  }

  /*
   * Use memcpy with known lengths rather than strcpy so we copy exact byte
   * counts (including the trailing NUL) while packing multiple strings into a
   * single caller-owned buffer.
   */
  memcpy(cursor, identity->name, identity->name_len + 1U);
  pwd->pw_name = cursor;
  cursor += identity->name_len + 1U;

  memcpy(cursor, passwd_value, passwd_len);
  pwd->pw_passwd = cursor;
  cursor += passwd_len;

  memcpy(cursor, gecos_value, gecos_len);
  pwd->pw_gecos = cursor;
  cursor += gecos_len;

  memcpy(cursor, home, home_len);
  pwd->pw_dir = cursor;
  cursor += home_len;

  memcpy(cursor, shell, shell_len);
  pwd->pw_shell = cursor;

  pwd->pw_uid = identity->uid;
  pwd->pw_gid = identity->uid;

  return NSS_STATUS_SUCCESS;
}

/*
 * Populate struct group using caller-provided storage.
 *
 * The module synthesizes only a primary group identity and deliberately leaves
 * gr_mem empty because SNAP_USER does not encode auxiliary group membership.
 */
static enum nss_status fill_group(const struct snap_identity *identity,
                                  struct group *grp, char *buffer,
                                  size_t buflen, int *errnop) {
  static const char passwd_value[] = "x";

  size_t name_len = identity->name_len + 1U;
  size_t passwd_len = sizeof(passwd_value);
  size_t members_len = sizeof(char *);
  size_t align_mask = _Alignof(char *) - 1U;
  uintptr_t raw_addr = (uintptr_t)buffer;
  uintptr_t members_addr = (raw_addr + align_mask) & ~(uintptr_t)align_mask;
  size_t members_offset = (size_t)(members_addr - raw_addr);
  size_t required = members_offset + members_len + name_len + passwd_len;
  char **members;
  char *cursor;

  if (required > buflen) {
    set_error(errnop, ERANGE);
    return NSS_STATUS_TRYAGAIN;
  }

  members = (char **)(void *)(buffer + members_offset);
  cursor = buffer + members_offset + members_len;

  memcpy(cursor, identity->name, name_len);
  grp->gr_name = cursor;
  cursor += name_len;

  memcpy(cursor, passwd_value, passwd_len);
  grp->gr_passwd = cursor;

  grp->gr_gid = (gid_t)identity->uid;
  grp->gr_mem = members;
  members[0] = NULL;

  return NSS_STATUS_SUCCESS;
}

/* NSS name lookup entry point for service "snapd". */
enum nss_status _nss_snapd_getpwnam_r(const char *name, struct passwd *pwd,
                                      char *buffer, size_t buflen,
                                      int *errnop) {
  struct snap_identity identity;
  enum nss_status status;

  if (name == NULL || pwd == NULL || buffer == NULL) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_UNAVAIL;
  }

  status = parse_snap_user(&identity, errnop);
  if (status != NSS_STATUS_SUCCESS) {
    return status;
  }

  /* Exact-name match only; all other users are delegated to next NSS service.
   */
  if (strcmp(name, identity.name) != 0) {
    set_error(errnop, ENOENT);
    return NSS_STATUS_NOTFOUND;
  }

  return fill_passwd(&identity, pwd, buffer, buflen, errnop);
}

/* NSS uid lookup entry point for service "snapd". */
enum nss_status _nss_snapd_getpwuid_r(uid_t uid, struct passwd *pwd,
                                      char *buffer, size_t buflen,
                                      int *errnop) {
  struct snap_identity identity;
  enum nss_status status;

  if (pwd == NULL || buffer == NULL) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_UNAVAIL;
  }

  status = parse_snap_user(&identity, errnop);
  if (status != NSS_STATUS_SUCCESS) {
    return status;
  }

  /* Exact-uid match only; mismatches fall through to other providers. */
  if (uid != identity.uid) {
    set_error(errnop, ENOENT);
    return NSS_STATUS_NOTFOUND;
  }

  return fill_passwd(&identity, pwd, buffer, buflen, errnop);
}

/* NSS group-name lookup entry point for service "snapd". */
enum nss_status _nss_snapd_getgrnam_r(const char *name, struct group *grp,
                                      char *buffer, size_t buflen,
                                      int *errnop) {
  struct snap_identity identity;
  enum nss_status status;

  if (name == NULL || grp == NULL || buffer == NULL) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_UNAVAIL;
  }

  status = parse_snap_user(&identity, errnop);
  if (status != NSS_STATUS_SUCCESS) {
    return status;
  }

  if (strcmp(name, identity.name) != 0) {
    set_error(errnop, ENOENT);
    return NSS_STATUS_NOTFOUND;
  }

  return fill_group(&identity, grp, buffer, buflen, errnop);
}

/* NSS group-id lookup entry point for service "snapd". */
enum nss_status _nss_snapd_getgrgid_r(gid_t gid, struct group *grp,
                                      char *buffer, size_t buflen,
                                      int *errnop) {
  struct snap_identity identity;
  enum nss_status status;

  if (grp == NULL || buffer == NULL) {
    set_error(errnop, EINVAL);
    return NSS_STATUS_UNAVAIL;
  }

  status = parse_snap_user(&identity, errnop);
  if (status != NSS_STATUS_SUCCESS) {
    return status;
  }

  if ((uintmax_t)gid != (uintmax_t)identity.uid) {
    set_error(errnop, ENOENT);
    return NSS_STATUS_NOTFOUND;
  }

  return fill_group(&identity, grp, buffer, buflen, errnop);
}

enum nss_status _nss_snapd_setpwent(int stayopen) {
  (void)stayopen;
  /* No internal iteration state is maintained in MVP mode. */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_snapd_getpwent_r(struct passwd *pwd, char *buffer,
                                      size_t buflen, int *errnop) {
  (void)pwd;
  (void)buffer;
  (void)buflen;

  /* Enumeration is intentionally unsupported in this minimal implementation. */
  set_error(errnop, ENOENT);
  return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_snapd_endpwent(void) { return NSS_STATUS_SUCCESS; }

enum nss_status _nss_snapd_setgrent(int stayopen) {
  (void)stayopen;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_snapd_getgrent_r(struct group *grp, char *buffer,
                                      size_t buflen, int *errnop) {
  (void)grp;
  (void)buffer;
  (void)buflen;

  set_error(errnop, ENOENT);
  return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_snapd_endgrent(void) { return NSS_STATUS_SUCCESS; }
