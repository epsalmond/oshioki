/* Test-only sudo approval plugin for docs/sudo-policy-query-spike.md.
 *
 * It uses the official sudo_plugin.h for sudo 1.9.15p5, invokes only the
 * read-only sudo list operation, records bounded synthetic metadata, and
 * always denies the outer request. It is never an authorization mechanism.
 */
#define _GNU_SOURCE

#include "sudo_plugin.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOG_PATH "/run/oshioki-sudo-query/plugin.log"
#define QUERY_PATH "/usr/bin/sudo"
#define QUERY_TIMEOUT_MS 2000
#define QUERY_OUTPUT_MAX 8192
#define ARRAY_MAX 128
#define VALUE_MAX 256

static char original_user[VALUE_MAX];
static unsigned long check_count;

static const char *array_value(char *const array[], const char *key) {
    size_t length = strlen(key);
    if (array == NULL) {
        return NULL;
    }
    for (size_t i = 0; array[i] != NULL; i++) {
        if (strncmp(array[i], key, length) == 0 && array[i][length] == '=') {
            return array[i] + length + 1;
        }
    }
    return NULL;
}

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
        if (byte >= 0x20 && byte <= 0x7e && byte != '\\') {
            out[i] = (char)byte;
        } else if (byte == '\\') {
            out[i] = '/';
        } else {
            out[i] = '?';
        }
    }
    out[i] = '\0';
}

static int copy_exact(char *out, size_t capacity, const char *value) {
    if (value == NULL) {
        out[0] = '\0';
        return 0;
    }
    size_t length = strnlen(value, capacity);
    if (length >= capacity) {
        out[0] = '\0';
        return 0;
    }
    memcpy(out, value, length + 1);
    return 1;
}

static int numeric_identity(char *out, size_t capacity, const char *value) {
    if (value == NULL || *value == '\0' || strlen(value) >= capacity - 2) {
        return 0;
    }
    for (size_t i = 0; value[i] != '\0'; i++) {
        if (value[i] < '0' || value[i] > '9') {
            return 0;
        }
    }
    int written = snprintf(out, capacity, "#%s", value);
    return written > 0 && (size_t)written < capacity;
}

static int environment_has(char *const environment[], const char *name) {
    size_t length = strlen(name);
    if (environment == NULL) {
        return 0;
    }
    for (size_t i = 0; environment[i] != NULL; i++) {
        if (strncmp(environment[i], name, length) == 0 &&
            environment[i][length] == '=') {
            return 1;
        }
    }
    return 0;
}

static size_t array_count(char *const array[]) {
    size_t count = 0;
    if (array != NULL) {
        while (array[count] != NULL && count < ARRAY_MAX) {
            count++;
        }
    }
    return count;
}

static int monotonic_ms(long long *milliseconds) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    *milliseconds = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    return 1;
}

static void append_sanitized(char *out, size_t capacity, size_t *length,
                             const char *bytes, size_t count) {
    for (size_t i = 0; i < count && *length + 1 < capacity; i++) {
        unsigned char byte = (unsigned char)bytes[i];
        if (byte >= 0x20 && byte <= 0x7e && byte != '\\') {
            out[(*length)++] = (char)byte;
        } else if (*length + 4 < capacity) {
            int written = snprintf(out + *length, capacity - *length,
                                   "\\x%02x", byte);
            if (written < 0) {
                break;
            }
            *length += (size_t)written;
        }
    }
    out[*length] = '\0';
}

static void write_log(const char *format, ...) {
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    char line[16384];
    va_list args;
    va_start(args, format);
    int written = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (written > 0) {
        size_t length = (size_t)written;
        if (length >= sizeof(line)) {
            length = sizeof(line) - 1;
        }
        (void)write(fd, line, length);
    }
    close(fd);
}

static int child_status_code(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

static void reset_child_state(void) {
    sigset_t empty;
    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    const int signals[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGCHLD, SIGPIPE,
        SIGALRM, SIGUSR1, SIGUSR2, SIGTSTP, SIGTTIN, SIGTTOU,
    };
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        (void)sigaction(signals[i], &action, NULL);
    }
}

static int parsed_child_euid(const char *output) {
    const char *marker = strstr(output, "QUERY_CHILD_EUID=");
    if (marker == NULL) {
        return -1;
    }
    char *end = NULL;
    long value = strtol(marker + strlen("QUERY_CHILD_EUID="), &end, 10);
    if (end == marker + strlen("QUERY_CHILD_EUID=") || value < 0 || value > INT_MAX) {
        return -1;
    }
    return (int)value;
}

static int run_policy_query(const char *runas_uid, const char *runas_gid,
                            char *const run_argv[], char *output,
                            size_t output_capacity, size_t *output_length,
                            int *timed_out, int *child_euid) {
    output[0] = '\0';
    *output_length = 0;
    *timed_out = 0;
    *child_euid = -1;
    if (original_user[0] == '\0' || runas_uid[0] == '\0') {
        return -4;
    }
    char *query_argv[ARRAY_MAX];
    size_t count = 0;
    query_argv[count++] = (char *)QUERY_PATH;
    query_argv[count++] = "-nkll";
    query_argv[count++] = "-U";
    query_argv[count++] = original_user;
    query_argv[count++] = "-u";
    query_argv[count++] = (char *)runas_uid;
    if (runas_gid[0] != '\0') {
        query_argv[count++] = "-g";
        query_argv[count++] = (char *)runas_gid;
    }
    query_argv[count++] = "--";
    for (size_t i = 0; run_argv != NULL && run_argv[i] != NULL; i++) {
        if (count + 2 >= ARRAY_MAX) {
            *output_length = 0;
            *timed_out = 0;
            *child_euid = -1;
            return -2;
        }
        query_argv[count++] = run_argv[i];
    }
    query_argv[count] = NULL;

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        *output_length = 0;
        *timed_out = 0;
        *child_euid = -1;
        return -3;
    }
    pid_t child = fork();
    if (child < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        *output_length = 0;
        *timed_out = 0;
        *child_euid = -1;
        return -3;
    }
    if (child == 0) {
        (void)setpgid(0, 0);
        reset_child_state();
        (void)dup2(pipe_fds[1], STDOUT_FILENO);
        (void)dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        if (setgroups(0, NULL) != 0 || setresgid(0, 0, 0) != 0 ||
            setresuid(0, 0, 0) != 0) {
            dprintf(STDERR_FILENO, "QUERY_PRIVILEGE_ERR=%d\n", errno);
            _exit(126);
        }
        char *query_env[] = {
            "LC_ALL=C",
            "LANG=C",
            "PATH=/usr/bin:/bin",
            "SUDO_QUERY_CHILD=1",
            NULL,
        };
        dprintf(STDERR_FILENO,
                "QUERY_CHILD_UID=%ld QUERY_CHILD_EUID=%ld "
                "QUERY_CHILD_GID=%ld QUERY_CHILD_EGID=%ld "
                "QUERY_CHILD_GROUPS=%d\n",
                (long)getuid(), (long)geteuid(), (long)getgid(),
                (long)getegid(), getgroups(0, NULL));
        execve(QUERY_PATH, query_argv, query_env);
        dprintf(STDERR_FILENO, "QUERY_EXEC_ERR=%d\n", errno);
        _exit(127);
    }
    (void)setpgid(child, child);
    close(pipe_fds[1]);
    int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
    }
    *output_length = 0;
    *timed_out = 0;
    *child_euid = -1;
    int status = 0;
    int finished = 0;
    long long started_at = 0;
    if (!monotonic_ms(&started_at)) {
        (void)kill(-child, SIGKILL);
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        close(pipe_fds[0]);
        return -5;
    }
    long long deadline = started_at + QUERY_TIMEOUT_MS;
    while (!finished) {
        char chunk[1024];
        ssize_t read_count = read(pipe_fds[0], chunk, sizeof(chunk));
        if (read_count > 0) {
            append_sanitized(output, output_capacity, output_length, chunk,
                             (size_t)read_count);
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            finished = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            finished = 1;
            status = 127 << 8;
            break;
        }
        long long now = 0;
        if (!monotonic_ms(&now)) {
            *timed_out = 1;
            (void)kill(-child, SIGKILL);
            (void)kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            finished = 1;
            break;
        }
        if (now >= deadline) {
            *timed_out = 1;
            (void)kill(-child, SIGKILL);
            (void)kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            finished = 1;
            break;
        }
        struct pollfd descriptor = {.fd = pipe_fds[0], .events = POLLIN};
        (void)poll(&descriptor, 1, 25);
    }
    for (;;) {
        char chunk[1024];
        ssize_t read_count = read(pipe_fds[0], chunk, sizeof(chunk));
        if (read_count <= 0) {
            break;
        }
        append_sanitized(output, output_capacity, output_length, chunk,
                         (size_t)read_count);
    }
    close(pipe_fds[0]);
    output[*output_length] = '\0';
    *child_euid = parsed_child_euid(output);
    return child_status_code(status);
}

static void log_check(char *const command_info[], char *const run_argv[],
                      char *const run_envp[], int query_status,
                      int query_timed_out, int query_child_euid,
                      const char *query_output) {
    char command[VALUE_MAX];
    char runas_user[VALUE_MAX];
    char runas_group[VALUE_MAX];
    char runas_uid[VALUE_MAX];
    char runas_gid[VALUE_MAX];
    const char *value = array_value(command_info, "command");
    safe_copy(command, sizeof(command), value);
    safe_copy(runas_user, sizeof(runas_user),
              array_value(command_info, "runas_user"));
    safe_copy(runas_group, sizeof(runas_group),
              array_value(command_info, "runas_group"));
    safe_copy(runas_uid, sizeof(runas_uid),
              array_value(command_info, "runas_uid"));
    safe_copy(runas_gid, sizeof(runas_gid),
              array_value(command_info, "runas_gid"));
    write_log("event=check count=%lu plugin_euid=%ld query_child_euid=%d "
              "original_user=%s runas_user=%s runas_group=%s runas_uid=%s "
              "runas_gid=%s command=%s "
              "argc=%zu env_count=%zu marker=%d query_status=%d timeout=%d "
              "classification=UNKNOWN decision=DENY query_output=%s\n",
              check_count, (long)geteuid(), query_child_euid, original_user,
              runas_user, runas_group, runas_uid, runas_gid, command,
              array_count(run_argv),
              array_count(run_envp), environment_has(run_envp, "SUDO_QUERY_MARKER"),
              query_status, query_timed_out, query_output);
}

static int plugin_open(unsigned int version, sudo_conv_t conversation,
                       sudo_printf_t sudo_plugin_printf,
                       char *const settings[], char *const user_info[],
                       int submit_optind, char *const submit_argv[],
                       char *const submit_envp[], char *const plugin_options[],
                       const char **errstr) {
    (void)version;
    (void)conversation;
    (void)sudo_plugin_printf;
    (void)settings;
    (void)submit_optind;
    (void)submit_argv;
    (void)submit_envp;
    (void)plugin_options;
    (void)errstr;
    if (array_value(submit_envp, "SUDO_QUERY_CHILD") != NULL) {
        write_log("event=nested_open nested=1\n");
        return -1;
    }
    (void)copy_exact(original_user, sizeof(original_user),
                     array_value(user_info, "user"));
    check_count = 0;
    return 1;
}

static int plugin_check(char *const command_info[], char *const run_argv[],
                        char *const run_envp[], const char **errstr) {
    (void)errstr;
    check_count++;
    char runas_uid[VALUE_MAX] = "";
    char runas_gid[VALUE_MAX] = "";
    (void)numeric_identity(runas_uid, sizeof(runas_uid),
                           array_value(command_info, "runas_uid"));
    (void)numeric_identity(runas_gid, sizeof(runas_gid),
                           array_value(command_info, "runas_gid"));
    char output[QUERY_OUTPUT_MAX];
    size_t output_length = 0;
    int timed_out = 0;
    int child_euid = -1;
    int status = run_policy_query(runas_uid, runas_gid, run_argv, output,
                                  sizeof(output), &output_length, &timed_out,
                                  &child_euid);
    log_check(command_info, run_argv, run_envp, status, timed_out, child_euid,
              output);
    return 0;
}

static void plugin_close(void) {}

static int plugin_show_version(int verbose) {
    (void)verbose;
    return 1;
}

struct approval_plugin approval_exec = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = plugin_open,
    .close = plugin_close,
    .check = plugin_check,
    .show_version = plugin_show_version,
};
