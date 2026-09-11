/* Test-only final-exec probe for docs/pam-migration-spike.md. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void safe_copy(char *out, size_t capacity, const char *value) {
    if (capacity == 0) {
        return;
    }
    if (value == NULL) {
        value = "";
    }
    size_t i = 0;
    for (; i + 1 < capacity && value[i] != '\0'; i++) {
        unsigned char byte = (unsigned char)value[i];
        out[i] = (byte >= 0x20 && byte <= 0x7e) ? (char)byte : '?';
    }
    out[i] = '\0';
}

static size_t environment_count(char **environment) {
    size_t count = 0;
    while (environment != NULL && environment[count] != NULL) {
        count++;
    }
    return count;
}

int main(int argc, char **argv, char **environment) {
    const char *path = "/run/oshioki-pam-spike/final.log";
    FILE *file = fopen(path, "a");
    if (file == NULL) {
        return 2;
    }
    const char *marker = getenv("PAM_SPIKE_MARKER");
    const char *sudo_user = getenv("SUDO_USER");
    const char *sudo_command = getenv("SUDO_COMMAND");
    char safe_user[128];
    char safe_command[512];
    safe_copy(safe_user, sizeof(safe_user), sudo_user);
    safe_copy(safe_command, sizeof(safe_command), sudo_command);
    fprintf(file, "pid=%ld uid=%ld euid=%ld argc=%d env_count=%zu "
                  "marker_present=%d sudo_user=%s sudo_command=%s\n",
            (long)getpid(), (long)getuid(), (long)geteuid(), argc,
            environment_count(environment), marker != NULL, safe_user,
            safe_command);
    for (int i = 0; i < argc; i++) {
        char safe_argument[256];
        safe_copy(safe_argument, sizeof(safe_argument), argv[i]);
        fprintf(file, "argv%d=%s\n", i, safe_argument);
    }
    fclose(file);
    return 0;
}
