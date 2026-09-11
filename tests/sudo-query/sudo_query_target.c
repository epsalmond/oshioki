/* Test-only command. It records execution metadata so a policy query cannot
 * be mistaken for running the command it lists. */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv, char **environment) {
    (void)environment;
    int fd = open("/run/oshioki-sudo-query/target.log",
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return 2;
    }
    dprintf(fd, "pid=%ld uid=%ld euid=%ld argc=%d\n", (long)getpid(),
            (long)getuid(), (long)geteuid(), argc);
    for (int i = 0; i < argc; i++) {
        dprintf(fd, "argv%d_len=%zu\n", i, strlen(argv[i]));
    }
    close(fd);
    return 0;
}
