/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2025 Michał Podsiadlik <michal@nglab.net>
 *
 * libssha is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libssha is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libssha. If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>

/*
 * OpenSSH is not using HOME environment variable directly, but is using
 * getpwnam and getpwuid to get home directory of the user.
 * We override these functions to return a fake home directory.
 *
 * This is used in integration tests to redirect OpenSSH to use a
 * temporary home directory.
 * 
 * The fake home directory is set in the FAKE_HOME environment variable.
 * This allows tests to run in a controlled environment.
 * 
 * This file is compiled into a shared library and loaded using LD_PRELOAD.
 * 
 * Usage:
 * export FAKE_HOME=/path/to/fake/home
 * export LD_PRELOAD=/path/to/libhome_replace.so
 */

 /**
  * Get password entry by name, overriding the home directory.
  */
struct passwd *getpwnam(const char *name)
{
    static struct passwd fake_pwd;
    static char home[256];

    struct passwd *(*orig_getpwnam)(const char *) = dlsym(RTLD_NEXT, "getpwnam");
    struct passwd *orig = orig_getpwnam(name);

    fake_pwd = *orig;

    snprintf(home, sizeof(home), "%s", getenv("FAKE_HOME"));
    fake_pwd.pw_dir = home;

    return &fake_pwd;
}

struct passwd *getpwuid(uid_t uid)
{
    static struct passwd fake_pwd;
    static char home[256];

    struct passwd *(*orig_getpwuid)(uid_t) = dlsym(RTLD_NEXT, "getpwuid");
    struct passwd *orig = orig_getpwuid(uid);

    fake_pwd = *orig;

    snprintf(home, sizeof(home), "%s", getenv("FAKE_HOME"));
    fake_pwd.pw_dir = home;

    return &fake_pwd;
}