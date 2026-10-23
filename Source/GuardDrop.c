// GuardDrop launches a program with its real, effective and saved group set to the
// packet-filter barrier group, so PF rules apply to the program and all of its
// children. It is installed at /Library/PrivilegedHelperTools/claudeproxyguard-drop
// (root:wheel, 0755) together with a NOPASSWD sudoers entry pinned to that path.
//
// The tool only REDUCES privileges: as root it changes ids to the invoking user and
// the unprivileged barrier group, then execs the target. It grants no capability the
// invoking user did not already have, so arbitrary target paths are acceptable; the
// target must still be a regular executable owned by the invoking user and must not
// be a setuid/setgid binary.
//
// Protocol: argv[1] is the absolute target path, remaining argv are its arguments.
// The environment is scrubbed; GUARD_ENV_FILE (an absolute path without control
// characters) is forwarded so the next stage can load the prepared session
// environment from a user-owned file.
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#define BARRIER_GROUP "_cpguard"

extern char **environ;

static int clean_environment(struct passwd *pw, const char *env_file) {
    static char home[MAXPATHLEN + 8], user[128], logname[128], tmpdir[MAXPATHLEN + 8], envfile[MAXPATHLEN + 16];
    static const char path[] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
    if (snprintf(home, sizeof home, "HOME=%s", pw->pw_dir) >= (int)sizeof home) return 80;
    if (snprintf(user, sizeof user, "USER=%s", pw->pw_name) >= (int)sizeof user) return 80;
    if (snprintf(logname, sizeof logname, "LOGNAME=%s", pw->pw_name) >= (int)sizeof logname) return 80;
    const char *tmp = getenv("TMPDIR");
    static char *list[7];
    int count = 0;
    list[count++] = (char *)path;
    list[count++] = home; list[count++] = user; list[count++] = logname;
    if (tmp && tmp[0] == '/' && strlen(tmp) < MAXPATHLEN && !strchr(tmp, '\n')) {
        if (snprintf(tmpdir, sizeof tmpdir, "TMPDIR=%s", tmp) >= (int)sizeof tmpdir) return 80;
        list[count++] = tmpdir;
    }
    if (env_file) {
        if (snprintf(envfile, sizeof envfile, "GUARD_ENV_FILE=%s", env_file) >= (int)sizeof envfile) return 80;
        list[count++] = envfile;
    }
    list[count] = NULL;
    environ = list;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/' || strlen(argv[1]) >= MAXPATHLEN || strchr(argv[1], '\n')) return 64;

    uid_t caller;
    const char *sudo_uid = getenv("SUDO_UID");
    if (geteuid() == 0) {
        if (!sudo_uid || !*sudo_uid) return 65; // root must invoke through sudo
        char *end = NULL; errno = 0;
        unsigned long value = strtoul(sudo_uid, &end, 10);
        if (errno || !end || *end != '\0' || value == 0 || value > 60000) return 65;
        caller = (uid_t)value;
    } else {
        return 71; // without root the barrier group cannot be applied: refuse
    }

    const char *env_file = getenv("GUARD_ENV_FILE");
    if (env_file && (env_file[0] != '/' || strlen(env_file) >= MAXPATHLEN || strchr(env_file, '\n'))) return 72;

    struct group *grp = getgrnam(BARRIER_GROUP);
    if (!grp) return 66;
    struct passwd *pw = getpwuid(caller);
    if (!pw || pw->pw_dir[0] != '/' || pw->pw_name[0] == '\0') return 67;

    char resolved[MAXPATHLEN];
    if (!realpath(argv[1], resolved)) return 68;
    struct stat meta;
    if (stat(resolved, &meta) < 0) return 68;
    if (!S_ISREG(meta.st_mode) || !(meta.st_mode & S_IXUSR)) return 69;
    if (meta.st_uid != caller) return 69; // only the caller's own executables
    if (meta.st_mode & (S_ISUID | S_ISGID)) return 69;

    if (setgid(grp->gr_gid) < 0) return 70;
    if (setgroups(1, &grp->gr_gid) < 0) return 70;
    if (setuid(caller) < 0) return 70;
    if (getuid() != caller || geteuid() != caller || getgid() != grp->gr_gid || getegid() != grp->gr_gid) return 70;

    int rc = clean_environment(pw, env_file);
    if (rc) return rc;

    execv(resolved, &argv[1]);
    return 73;
}
