/*
 * pam_fpd.so: fingerprint authentication through fpd.
 *
 * The module asks fpd to verify the user PAM is authenticating and maps the
 * answer onto PAM's codes. It does no USB, no cryptography and no parsing
 * beyond fpd's fixed-size frames; everything that touches the sensor lives
 * in fpd. Only a match grants, only a non-matching finger denies; anything
 * else (fpd not running, sensor busy or unavailable, nothing enrolled, a
 * remote session, a timeout) is PAM_AUTHINFO_UNAVAIL, so a stack with
 * "auth sufficient pam_fpd.so" carries on to the password.
 *
 * Arguments:
 *   timeout=SECONDS   how long to wait for a finger (default 15, max 120)
 *   max-tries=N       non-matching fingers allowed (default 3)
 *   socket=PATH       fpd's socket (default /run/fpd/fpd.sock)
 *   debug             log each outcome to syslog
 */
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "fpd_client.h"
#include "fpd_proto.h"

#define EXPORT __attribute__((visibility("default")))

#define DEFAULT_TIMEOUT_S 15U
#define MAX_TIMEOUT_S 120U
#define DEFAULT_TRIES 3U
#define MAX_TRIES 10U

struct args {
    uint32_t timeout_s;
    uint32_t max_tries;
    const char *socket;
    int debug;
};

/* Parses an unsigned decimal in [1, max], or returns 0. */
static uint32_t parse_count(const char *s, uint32_t max)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v == 0 || v > max || s[0] == '-')
        return 0;
    return (uint32_t)v;
}

static void parse_args(pam_handle_t *pamh, int argc, const char **argv, struct args *a)
{
    a->timeout_s = DEFAULT_TIMEOUT_S;
    a->max_tries = DEFAULT_TRIES;
    a->socket = FPD_SOCKET_PATH;
    a->debug = 0;
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        uint32_t timeout = strncmp(arg, "timeout=", 8) == 0 ? parse_count(arg + 8, MAX_TIMEOUT_S) : 0;
        uint32_t tries = strncmp(arg, "max-tries=", 10) == 0 ? parse_count(arg + 10, MAX_TRIES) : 0;
        if (timeout != 0)
            a->timeout_s = timeout;
        else if (tries != 0)
            a->max_tries = tries;
        else if (strncmp(arg, "socket=", 7) == 0 && arg[7] != '\0')
            a->socket = arg + 7;
        else if (strcmp(arg, "debug") == 0)
            a->debug = 1;
        else
            pam_syslog(pamh, LOG_WARNING, "ignoring argument \"%s\"", arg);
    }
}

struct conv {
    pam_handle_t *pamh;
    int silent;
};

/* Relays fpd's events to the user through the PAM conversation. */
static void on_event(void *ctx, uint16_t type, uint32_t value)
{
    const struct conv *c = ctx;
    if (c->silent)
        return;
    if (type == FPD_EV_PROMPT)
        (void)pam_info(c->pamh, "Place your finger on the fingerprint reader");
    else if (type == FPD_EV_RETRY && value == FPD_RETRY_NO_MATCH)
        (void)pam_info(c->pamh, "Fingerprint not recognised, try again");
    else if (type == FPD_EV_RETRY)
        (void)pam_info(c->pamh, "Fingerprint scan not usable, try again");
}

static const char *result_name(uint32_t r)
{
    static const char *const names[] = {
        "match",       "no match",    "nothing enrolled", "sensor unavailable",
        "sensor busy", "timed out",   "denied",           "bad request",
        "error",       "cancelled",   "already enrolled", "remote session",
    };
    return r < sizeof names / sizeof names[0] ? names[r] : "unknown result";
}

/* Maps fpd's result onto a PAM code. Only MATCH grants and only NO_MATCH
 * denies; everything else lets the stack fall back to the password. */
static int pam_code(uint32_t result)
{
    switch (result) {
    case FPD_RESULT_MATCH:
        return PAM_SUCCESS;
    case FPD_RESULT_NO_MATCH:
        return PAM_AUTH_ERR;
    default:
        return PAM_AUTHINFO_UNAVAIL;
    }
}

static int lookup_uid(pam_handle_t *pamh, const char *user, uid_t *uid)
{
    /* Large enough for any passwd entry glibc returns from files; a
     * bigger one fails the lookup, which only means no fingerprint. */
    char buf[16384];
    struct passwd pw;
    struct passwd *found = NULL;
    int err = getpwnam_r(user, &pw, buf, sizeof buf, &found);
    if (err != 0 || found == NULL) {
        pam_syslog(pamh, LOG_NOTICE, "unknown user \"%s\"", user);
        return PAM_USER_UNKNOWN;
    }
    *uid = pw.pw_uid;
    return PAM_SUCCESS;
}

EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct args a;
    parse_args(pamh, argc, argv, &a);

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || user[0] == '\0')
        return PAM_AUTHINFO_UNAVAIL;
    uid_t uid;
    int rc = lookup_uid(pamh, user, &uid);
    if (rc != PAM_SUCCESS)
        return rc;

    struct fpd_verify_opts opts = {
        .socket_path = a.socket,
        .uid = (uint32_t)uid,
        .timeout_ms = a.timeout_s * 1000U,
        .max_tries = a.max_tries,
    };
    struct conv c = {.pamh = pamh, .silent = ((unsigned int)flags & PAM_SILENT) != 0};
    uint32_t result = 0;
    fpd_status st = fpd_verify(&opts, on_event, &c, &result);
    if (st != FPD_OK) {
        pam_syslog(pamh, st == FPD_ERR_CONNECT ? LOG_INFO : LOG_ERR, "fpd: %s", fpd_last_error());
        return PAM_AUTHINFO_UNAVAIL;
    }
    if (a.debug || result != FPD_RESULT_MATCH)
        pam_syslog(pamh, result == FPD_RESULT_NO_MATCH ? LOG_NOTICE : LOG_INFO,
                   "fingerprint for %s: %s", user, result_name(result));
    if (result == FPD_RESULT_NO_MATCH && !c.silent)
        (void)pam_error(pamh, "Fingerprint not recognised");
    return pam_code(result);
}

EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
