/* Test-only PAM module for docs/pam-migration-spike.md.
 *
 * It deliberately reads no PAM_AUTHTOK and records no secret. The mode and
 * log paths are supplied by the disposable container's private PAM service.
 */
#define _GNU_SOURCE

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *option_value(int argc, const char **argv, const char *name,
                                const char *fallback) {
    size_t length = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], name, length) == 0 && argv[i][length] == '=') {
            return argv[i] + length + 1;
        }
    }
    return fallback;
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
        out[i] = (byte >= 0x20 && byte <= 0x7e) ? (char)byte : '?';
    }
    out[i] = '\0';
}

static int has_marker(char *const *environment) {
    if (environment == NULL) {
        return 0;
    }
    for (size_t i = 0; environment[i] != NULL; i++) {
        if (strncmp(environment[i], "PAM_SPIKE_MARKER=", 18) == 0) {
            return 1;
        }
    }
    return 0;
}

static size_t environment_count(char *const *environment) {
    size_t count = 0;
    if (environment != NULL) {
        while (environment[count] != NULL) {
            count++;
        }
    }
    return count;
}

static void read_process_cmdline(char *out, size_t capacity) {
    if (capacity == 0) {
        return;
    }
    FILE *file = fopen("/proc/self/cmdline", "rb");
    if (file == NULL) {
        out[0] = '\0';
        return;
    }
    size_t length = fread(out, 1, capacity - 1, file);
    fclose(file);
    for (size_t i = 0; i < length; i++) {
        if (out[i] == '\0') {
            out[i] = ' ';
        }
    }
    out[length] = '\0';
}

static void log_record(const char *path, const char *call, const char *mode,
                       const pam_handle_t *pamh, int argc,
                       const char **argv) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }

    const void *item = NULL;
    const char *service = "";
    const char *tty = "";
    const char *rhost = "";
    const char *ruser = "";
    const char *user = "";
    (void)pam_get_item(pamh, PAM_SERVICE, &item);
    service = item == NULL ? "" : (const char *)item;
    item = NULL;
    (void)pam_get_item(pamh, PAM_TTY, &item);
    tty = item == NULL ? "" : (const char *)item;
    item = NULL;
    (void)pam_get_item(pamh, PAM_RHOST, &item);
    rhost = item == NULL ? "" : (const char *)item;
    item = NULL;
    (void)pam_get_item(pamh, PAM_RUSER, &item);
    ruser = item == NULL ? "" : (const char *)item;
    (void)pam_get_user((pam_handle_t *)pamh, &user, NULL);

    char safe_service[128];
    char safe_tty[128];
    char safe_rhost[128];
    char safe_ruser[128];
    char safe_user[128];
    char process_cmdline[1024];
    safe_copy(safe_service, sizeof(safe_service), service);
    safe_copy(safe_tty, sizeof(safe_tty), tty);
    safe_copy(safe_rhost, sizeof(safe_rhost), rhost);
    safe_copy(safe_ruser, sizeof(safe_ruser), ruser);
    safe_copy(safe_user, sizeof(safe_user), user);
    read_process_cmdline(process_cmdline, sizeof(process_cmdline));

    char **pam_environment = pam_getenvlist((pam_handle_t *)pamh);
    extern char **environ;
    dprintf(fd,
            "call=%s mode=%s service=%s user=%s tty=%s rhost=%s ruser=%s "
            "pam_env_count=%zu pam_marker=%d process_env_count=%zu "
            "process_marker=%d argc=%d proc_cmdline=%s",
            call, mode, safe_service, safe_user, safe_tty, safe_rhost,
            safe_ruser, environment_count(pam_environment),
            has_marker(pam_environment), environment_count(environ),
            has_marker(environ), argc, process_cmdline);
    for (int i = 0; i < argc; i++) {
        char safe_argument[256];
        safe_copy(safe_argument, sizeof(safe_argument), argv[i]);
        dprintf(fd, " pam_arg%d=%s", i, safe_argument);
    }
    dprintf(fd, "\n");
    if (pam_environment != NULL) {
        for (size_t i = 0; pam_environment[i] != NULL; i++) {
            free(pam_environment[i]);
        }
        free(pam_environment);
    }
    close(fd);
}

static int configured_service(const pam_handle_t *pamh) {
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS || item == NULL) {
        return 0;
    }
    return strcmp((const char *)item, "sudo") == 0;
}

static int configured_mode(int argc, const char **argv, const char *mode_path,
                           char *mode, size_t capacity) {
    const char *path = option_value(argc, argv, "mode_file", mode_path);
    FILE *file = fopen(path, "r");
    if (file == NULL || fgets(mode, (int)capacity, file) == NULL) {
        if (file != NULL) {
            fclose(file);
        }
        return PAM_SYSTEM_ERR;
    }
    fclose(file);
    mode[strcspn(mode, "\r\n")] = '\0';
    if (strcmp(mode, "approve") == 0) {
        return PAM_SUCCESS;
    }
    if (strcmp(mode, "deny") == 0) {
        return PAM_AUTH_ERR;
    }
    if (strcmp(mode, "unavailable") == 0) {
        return PAM_AUTHINFO_UNAVAIL;
    }
    return PAM_SYSTEM_ERR;
}

static int run_authenticate(pam_handle_t *pamh, int argc, const char **argv) {
    const char *mode_path = "/run/oshioki-pam-spike/mode";
    const char *log_path = "/run/oshioki-pam-spike/pam.log";
    const char *configured_log = option_value(argc, argv, "log_file", log_path);
    char mode[64] = "";
    int result = configured_mode(argc, argv, mode_path, mode, sizeof(mode));
    log_record(configured_log, "auth", mode, pamh, argc, argv);
    return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)flags;
    if (!configured_service(pamh)) {
        return PAM_SERVICE_ERR;
    }
    return run_authenticate(pamh, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)flags;
    if (!configured_service(pamh)) {
        return PAM_SERVICE_ERR;
    }
    const char *log_path = option_value(
        argc, argv, "log_file", "/run/oshioki-pam-spike/pam.log");
    log_record(log_path, "acct", "", pamh, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
