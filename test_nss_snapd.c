// SPDX-FileCopyrightText: 2026 Zygmunt Krynicki
// SPDX-License-Identifier: LGPL-3.0-only

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

enum nss_status _nss_snapd_getpwnam_r(const char *name, struct passwd *pwd,
                                      char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_snapd_getpwuid_r(uid_t uid, struct passwd *pwd,
                                      char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_snapd_setpwent(int stayopen);
enum nss_status _nss_snapd_getpwent_r(struct passwd *pwd, char *buffer,
                                      size_t buflen, int *errnop);
enum nss_status _nss_snapd_endpwent(void);

static int failures;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "FAIL: %s\n", (msg));                                    \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static int is_in_buffer(const char *ptr, const char *buffer, size_t buflen) {
  if (ptr == NULL) {
    return 0;
  }
  return ptr >= buffer && ptr < (buffer + buflen);
}

static void test_missing_snap_user(void) {
  struct passwd pwd;
  char buffer[256];
  int err = 0;
  enum nss_status status;

  unsetenv("SNAP_USER");

  status = _nss_snapd_getpwnam_r("alice", &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_NOTFOUND,
        "missing SNAP_USER should return NOTFOUND");
  CHECK(err == ENOENT, "missing SNAP_USER should set ENOENT");
}

static void test_malformed_snap_user(void) {
  const char *malformed_values[] = {"",      "abc:alice", "1000",
                                    "1000:", ":alice",    "1000:alice:extra"};
  size_t i;

  for (i = 0; i < sizeof(malformed_values) / sizeof(malformed_values[0]); i++) {
    struct passwd pwd;
    char buffer[256];
    int err = 0;
    enum nss_status status;

    setenv("SNAP_USER", malformed_values[i], 1);
    status = _nss_snapd_getpwnam_r("alice", &pwd, buffer, sizeof(buffer), &err);
    CHECK(status == NSS_STATUS_NOTFOUND,
          "malformed SNAP_USER should return NOTFOUND");
    CHECK(err == EINVAL || err == ENOENT,
          "malformed SNAP_USER should set EINVAL or ENOENT");
  }
}

static void test_success_name_and_uid_lookup(void) {
  struct passwd pwd;
  char buffer[512];
  int err = 0;
  enum nss_status status;

  setenv("SNAP_USER", "1000:alice", 1);
  setenv("SNAP_REAL_HOME", "/home/alice", 1);
  setenv("SHELL", "/bin/bash", 1);

  status = _nss_snapd_getpwnam_r("alice", &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_SUCCESS, "name lookup should return SUCCESS");
  CHECK(strcmp(pwd.pw_name, "alice") == 0,
        "pw_name should match SNAP_USER name");
  CHECK(pwd.pw_uid == 1000, "pw_uid should match SNAP_USER uid");
  CHECK(pwd.pw_gid == 1000, "pw_gid should equal uid");
  CHECK(strcmp(pwd.pw_dir, "/home/alice") == 0,
        "pw_dir should come from SNAP_REAL_HOME");
  CHECK(strcmp(pwd.pw_shell, "/bin/bash") == 0,
        "pw_shell should come from SHELL");
  CHECK(strcmp(pwd.pw_passwd, "x") == 0, "pw_passwd should be x");
  CHECK(strcmp(pwd.pw_gecos, "") == 0, "pw_gecos should be empty");

  CHECK(is_in_buffer(pwd.pw_name, buffer, sizeof(buffer)),
        "pw_name should point to caller buffer");
  CHECK(is_in_buffer(pwd.pw_passwd, buffer, sizeof(buffer)),
        "pw_passwd should point to caller buffer");
  CHECK(is_in_buffer(pwd.pw_gecos, buffer, sizeof(buffer)),
        "pw_gecos should point to caller buffer");
  CHECK(is_in_buffer(pwd.pw_dir, buffer, sizeof(buffer)),
        "pw_dir should point to caller buffer");
  CHECK(is_in_buffer(pwd.pw_shell, buffer, sizeof(buffer)),
        "pw_shell should point to caller buffer");

  status = _nss_snapd_getpwuid_r(1000, &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_SUCCESS, "uid lookup should return SUCCESS");
  CHECK(strcmp(pwd.pw_name, "alice") == 0,
        "uid lookup should return same identity");
}

static void test_non_match_returns_notfound(void) {
  struct passwd pwd;
  char buffer[256];
  int err = 0;
  enum nss_status status;

  setenv("SNAP_USER", "1000:alice", 1);

  status = _nss_snapd_getpwnam_r("bob", &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_NOTFOUND, "name mismatch should return NOTFOUND");
  CHECK(err == ENOENT, "name mismatch should set ENOENT");

  status = _nss_snapd_getpwuid_r(1001, &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_NOTFOUND, "uid mismatch should return NOTFOUND");
  CHECK(err == ENOENT, "uid mismatch should set ENOENT");
}

static void test_fallback_values(void) {
  struct passwd pwd;
  char buffer[256];
  int err = 0;
  enum nss_status status;

  setenv("SNAP_USER", "1000:alice", 1);
  unsetenv("SNAP_REAL_HOME");
  unsetenv("SHELL");

  status = _nss_snapd_getpwnam_r("alice", &pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_SUCCESS,
        "lookup should still succeed with missing optional env vars");
  CHECK(strcmp(pwd.pw_dir, "/nonexistent") == 0,
        "missing SNAP_REAL_HOME should use /nonexistent");
  CHECK(strcmp(pwd.pw_shell, "/bin/false") == 0,
        "missing SHELL should use /bin/false");
}

static void test_small_buffer(void) {
  struct passwd pwd;
  char tiny[8];
  int err = 0;
  enum nss_status status;

  setenv("SNAP_USER", "1000:alice", 1);
  setenv("SNAP_REAL_HOME", "/home/alice", 1);
  setenv("SHELL", "/bin/bash", 1);

  status = _nss_snapd_getpwnam_r("alice", &pwd, tiny, sizeof(tiny), &err);
  CHECK(status == NSS_STATUS_TRYAGAIN, "small buffer should return TRYAGAIN");
  CHECK(err == ERANGE, "small buffer should set ERANGE");
}

static void test_enumeration_entrypoints(void) {
  struct passwd pwd;
  char buffer[128];
  int err = 0;
  enum nss_status status;

  status = _nss_snapd_setpwent(0);
  CHECK(status == NSS_STATUS_SUCCESS, "setpwent should return SUCCESS");

  status = _nss_snapd_getpwent_r(&pwd, buffer, sizeof(buffer), &err);
  CHECK(status == NSS_STATUS_NOTFOUND,
        "getpwent_r should return NOTFOUND for MVP");
  CHECK(err == ENOENT, "getpwent_r should set ENOENT");

  status = _nss_snapd_endpwent();
  CHECK(status == NSS_STATUS_SUCCESS, "endpwent should return SUCCESS");
}

int main(void) {
  test_missing_snap_user();
  test_malformed_snap_user();
  test_success_name_and_uid_lookup();
  test_non_match_returns_notfound();
  test_fallback_values();
  test_small_buffer();
  test_enumeration_entrypoints();

  if (failures != 0) {
    fprintf(stderr, "%d test failure(s)\n", failures);
    return 1;
  }

  printf("All NSS module tests passed\n");
  return 0;
}
