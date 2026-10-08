/*
 * pam_fpd's PAM glue, with libpam replaced: pam_get_user, pam_prompt
 * (which pam_info and pam_error expand to) and pam_syslog are defined
 * here and record what the module does.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include <cmocka.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "fake_fpd.h"
#include "fpd_proto.h"

static const char *mock_user;
static int mock_get_user_rc;
static char messages[1024];
static char syslogged[1024];

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)pamh;
    (void)prompt;
    *user = mock_user;
    return mock_get_user_rc;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...)
{
    (void)pamh;
    (void)response;
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    size_t used = strlen(messages);
    (void)snprintf(messages + used, sizeof messages - used, "%s:%s\n",
                   style == PAM_ERROR_MSG ? "error" : "info", line);
    return PAM_SUCCESS;
}

void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    (void)pamh;
    (void)priority;
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    size_t used = strlen(syslogged);
    (void)snprintf(syslogged + used, sizeof syslogged - used, "%s\n", line);
}

/* libpam declares the handle non-null; it is never dereferenced here, but
 * passing NULL would be a lie the sanitizer rightly reports. */
static int dummy_handle;
#define PAMH ((pam_handle_t *)&dummy_handle)

static char me[64];
static char sockarg[160];

static int setup(void **state)
{
    (void)state;
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL)
        return -1;
    (void)snprintf(me, sizeof me, "%s", pw->pw_name);
    mock_user = me;
    mock_get_user_rc = PAM_SUCCESS;
    messages[0] = '\0';
    syslogged[0] = '\0';
    return 0;
}

/* Runs pam_sm_authenticate against a fake fpd sending reply. */
static int auth(struct fake_fpd *f, const uint8_t *reply, size_t len, int flags, int argc,
                const char **extra)
{
    fake_fpd_start(f, reply, len);
    (void)snprintf(sockarg, sizeof sockarg, "socket=%s", f->path);
    const char *argv[8] = {sockarg};
    for (int i = 0; i < argc && i < 7; i++)
        argv[i + 1] = extra[i];
    int rc = pam_sm_authenticate(PAMH, flags, argc + 1, argv);
    fake_fpd_stop(f);
    return rc;
}

static size_t script(uint8_t *r, uint32_t result)
{
    size_t n = frame_empty(r, FPD_EV_PROMPT);
    n += frame_u32(r + n, FPD_EV_RETRY, FPD_RETRY_SCAN);
    n += frame_u32(r + n, FPD_EV_RETRY, FPD_RETRY_NO_MATCH);
    return n + frame_u32(r + n, FPD_EV_RESULT, result);
}

static void test_match(void **state)
{
    (void)state;
    uint8_t r[64];
    struct fake_fpd f = {0};
    assert_int_equal(auth(&f, r, script(r, FPD_RESULT_MATCH), 0, 0, NULL), PAM_SUCCESS);
    assert_non_null(strstr(messages, "info:Place your finger"));
    assert_non_null(strstr(messages, "info:Fingerprint scan not usable"));
    assert_non_null(strstr(messages, "info:Fingerprint not recognised, try again"));
    assert_null(strstr(syslogged, "fingerprint for")); /* quiet without debug */
    /* uid in the request is ours */
    uint32_t uid = (uint32_t)f.request[4] | (uint32_t)f.request[5] << 8 |
                   (uint32_t)f.request[6] << 16 | (uint32_t)f.request[7] << 24;
    assert_int_equal(uid, getuid());
}

static void test_results(void **state)
{
    (void)state;
    const struct {
        uint32_t result;
        int want;
    } cases[] = {
        {FPD_RESULT_NO_MATCH, PAM_AUTH_ERR},
        {FPD_RESULT_NOT_ENROLLED, PAM_AUTHINFO_UNAVAIL},
        {FPD_RESULT_BUSY, PAM_AUTHINFO_UNAVAIL},
        {FPD_RESULT_TIMEOUT, PAM_AUTHINFO_UNAVAIL},
        {FPD_RESULT_REMOTE, PAM_AUTHINFO_UNAVAIL},
        {FPD_RESULT_DENIED, PAM_AUTHINFO_UNAVAIL},
        {200, PAM_AUTHINFO_UNAVAIL},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t r[8];
        struct fake_fpd f = {0};
        assert_int_equal(auth(&f, r, frame_u32(r, FPD_EV_RESULT, cases[i].result), 0, 0, NULL),
                         cases[i].want);
    }
    assert_non_null(strstr(messages, "error:Fingerprint not recognised"));
    assert_non_null(strstr(syslogged, "sensor busy"));
    assert_non_null(strstr(syslogged, "unknown result"));
}

static void test_silent(void **state)
{
    (void)state;
    uint8_t r[64];
    struct fake_fpd f = {0};
    assert_int_equal(auth(&f, r, script(r, FPD_RESULT_NO_MATCH), PAM_SILENT, 0, NULL), PAM_AUTH_ERR);
    assert_string_equal(messages, "");
}

static void test_arguments(void **state)
{
    (void)state;
    uint8_t r[8];
    struct fake_fpd f = {0};
    const char *args[] = {"timeout=30", "max-tries=5", "debug", "bogus", "timeout=0",
                          "max-tries=x", "socket="};
    assert_int_equal(auth(&f, r, frame_u32(r, FPD_EV_RESULT, FPD_RESULT_MATCH), 0, 7, args),
                     PAM_SUCCESS);
    /* timeout=30 and max-tries=5 reached fpd; the bad values were ignored */
    assert_int_equal(f.request[8] | f.request[9] << 8, 30000);
    assert_int_equal(f.request[12], 5);
    assert_non_null(strstr(syslogged, "ignoring argument \"bogus\""));
    assert_non_null(strstr(syslogged, "ignoring argument \"timeout=0\""));
    assert_non_null(strstr(syslogged, "fingerprint for")); /* debug */
}

static void test_no_fpd(void **state)
{
    (void)state;
    const char *argv[] = {"socket=/nonexistent/fpd.sock"};
    assert_int_equal(pam_sm_authenticate(PAMH, 0, 1, argv), PAM_AUTHINFO_UNAVAIL);
    assert_non_null(strstr(syslogged, "fpd: connect"));
}

static void test_user_problems(void **state)
{
    (void)state;
    const char *argv[] = {"socket=/nonexistent/fpd.sock"};
    mock_user = "no-such-user-at-all";
    assert_int_equal(pam_sm_authenticate(PAMH, 0, 1, argv), PAM_USER_UNKNOWN);
    mock_user = "";
    assert_int_equal(pam_sm_authenticate(PAMH, 0, 1, argv), PAM_AUTHINFO_UNAVAIL);
    mock_user = me;
    mock_get_user_rc = PAM_CONV_ERR;
    assert_int_equal(pam_sm_authenticate(PAMH, 0, 1, argv), PAM_AUTHINFO_UNAVAIL);
}

static void test_setcred(void **state)
{
    (void)state;
    assert_int_equal(pam_sm_setcred(PAMH, 0, 0, NULL), PAM_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_match, setup),
        cmocka_unit_test_setup(test_results, setup),
        cmocka_unit_test_setup(test_silent, setup),
        cmocka_unit_test_setup(test_arguments, setup),
        cmocka_unit_test_setup(test_no_fpd, setup),
        cmocka_unit_test_setup(test_user_problems, setup),
        cmocka_unit_test(test_setcred),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
