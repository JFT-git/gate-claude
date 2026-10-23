// Map Foundation Process stdin/stdout to the runtime adapter's private JSON pipe.
// This opens no TCP debugging port and installs no certificates.
//
// When GUARD_ENV_FILE is set (network-barrier launches through the privilege-drop
// helper scrub the environment), the session environment is restored from that
// file before exec. The file must be a regular file owned by this user, mode
// 0600, at most 64 KiB, with strict KEY=VALUE lines.
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define GUARD_ENV_MAX 65536

extern char **environ;

static int key_byte(char c, int first) {
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c == '_') return 1;
    return !first && c >= '0' && c <= '9';
}

static int load_env_file(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 74;
    struct stat meta;
    if (fstat(fd, &meta) < 0) { close(fd); return 74; }
    if (!S_ISREG(meta.st_mode) || meta.st_uid != getuid() || (meta.st_mode & 077) != 0) { close(fd); return 75; }
    if (meta.st_size <= 0 || meta.st_size > GUARD_ENV_MAX) { close(fd); return 76; }
    char *buffer = malloc((size_t)meta.st_size);
    if (!buffer) { close(fd); return 77; }
    ssize_t total = 0;
    while (total < meta.st_size) {
        ssize_t chunk = read(fd, buffer + total, (size_t)(meta.st_size - total));
        if (chunk <= 0) { close(fd); return 77; }
        total += chunk;
    }
    close(fd);
    if (buffer[total - 1] != '\n') return 78;
    int lines = 0;
    for (ssize_t i = 0; i < total; i++) if (buffer[i] == '\n') lines++;
    char **restored = calloc((size_t)lines + 1, sizeof(char *));
    if (!restored) return 77;
    int count = 0;
    ssize_t start = 0;
    for (ssize_t i = 0; i < total; i++) {
        if (buffer[i] != '\n') continue;
        buffer[i] = '\0';
        char *line = buffer + start;
        start = i + 1;
        if (!*line) continue;
        char *equals = strchr(line, '=');
        if (!equals || equals == line) return 78;
        for (char *p = line; p < equals; p++) if (!key_byte(*p, p == line)) return 78;
        if (strncmp(line, "DYLD_", 5) == 0) continue; // never honour injected loader variables
        restored[count++] = line;
    }
    if (count == 0) return 78;
    restored[count] = NULL;
    environ = restored;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/') return 64;
    const char *env_file = getenv("GUARD_ENV_FILE");
    if (env_file) {
        int loaded = load_env_file(env_file);
        if (loaded) return loaded;
    }
    if (setpgid(0, 0) < 0 && getpgrp() != getpid()) return 70;
    if (dup2(STDIN_FILENO, 3) < 0 || dup2(STDOUT_FILENO, 4) < 0) return 70;
    if (fcntl(3, F_SETFD, 0) < 0 || fcntl(4, F_SETFD, 0) < 0) return 70;
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) return 70;
    dup2(nullfd, 0); dup2(nullfd, 1);
#ifndef GUARD_HOST_TEST
    dup2(nullfd, 2);
#endif
    if (nullfd > 4) close(nullfd);
    signal(SIGPIPE, SIG_DFL);
    execv(argv[1], &argv[1]);
    return 71;
}
