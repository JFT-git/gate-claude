// Map Foundation Process stdin/stdout to the runtime adapter's private JSON pipe.
// This opens no TCP debugging port and installs no certificates.
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/') return 64;
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
