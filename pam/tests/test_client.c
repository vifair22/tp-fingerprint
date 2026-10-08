#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "fake_fpd.h"
#include "fpd_client.h"
#include "fpd_proto.h"

struct events {
    int prompts;
    int retries;
    uint32_t last_reason;
};

static void record(void *ctx, uint16_t type, uint32_t value)
{
    struct events *e = ctx;
    if (type == FPD_EV_PROMPT)
        e->prompts++;
    if (type == FPD_EV_RETRY) {
        e->retries++;
        e->last_reason = value;
    }
}

static fpd_status run(struct fake_fpd *f, const uint8_t *reply, size_t len, struct events *e,
                      uint32_t *result)
{
    fake_fpd_start(f, reply, len);
    struct fpd_verify_opts o = {.socket_path = f->path, .uid = 1000, .timeout_ms = 200, .max_tries = 3};
    fpd_status st = fpd_verify(&o, record, e, result);
    fake_fpd_stop(f);
    return st;
}

static void test_match_with_events(void **state)
{
    (void)state;
    uint8_t r[64];
    size_t n = frame_empty(r, FPD_EV_PROMPT);
    n += frame_u32(r + n, FPD_EV_RETRY, FPD_RETRY_SCAN);
    n += frame_u32(r + n, FPD_EV_RETRY, FPD_RETRY_NO_MATCH);
    n += frame_empty(r + n, FPD_EV_PROMPT);
    n += frame_u32(r + n, FPD_EV_RESULT, FPD_RESULT_MATCH);
    struct fake_fpd f = {0};
    struct events e = {0, 0, 0};
    uint32_t result = 99;
    assert_int_equal(run(&f, r, n, &e, &result), FPD_OK);
    assert_int_equal(result, FPD_RESULT_MATCH);
    assert_int_equal(e.prompts, 2);
    assert_int_equal(e.retries, 2);
    assert_int_equal(e.last_reason, FPD_RETRY_NO_MATCH);

    /* The request: VERIFY, 12 bytes, uid 1000, 200 ms, 3 tries. */
    const uint8_t want[] = {0x01, 0x00, 0x0c, 0x00, 0xe8, 0x03, 0x00, 0x00,
                            0xc8, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    assert_int_equal(f.request_len, sizeof want);
    assert_memory_equal(f.request, want, sizeof want);
}

static void test_results_pass_through(void **state)
{
    (void)state;
    const uint32_t codes[] = {FPD_RESULT_NO_MATCH, FPD_RESULT_BUSY, FPD_RESULT_REMOTE, 77};
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        uint8_t r[8];
        size_t n = frame_u32(r, FPD_EV_RESULT, codes[i]);
        struct fake_fpd f = {0};
        struct events e = {0, 0, 0};
        uint32_t result = 0;
        assert_int_equal(run(&f, r, n, &e, &result), FPD_OK);
        assert_int_equal(result, codes[i]);
    }
}

static void test_protocol_errors(void **state)
{
    (void)state;
    uint8_t unknown[8], wrong_len[8];
    size_t n1 = frame_u32(unknown, 0x0085, 1); /* a FINGER frame: not for us */
    size_t n2 = frame_u32(wrong_len, FPD_EV_PROMPT, 0);
    struct fake_fpd f = {0};
    struct events e = {0, 0, 0};
    uint32_t result = 0;
    assert_int_equal(run(&f, unknown, n1, &e, &result), FPD_ERR_PROTOCOL);
    assert_non_null(strstr(fpd_last_error(), "0x0085"));
    assert_int_equal(run(&f, wrong_len, n2, &e, &result), FPD_ERR_PROTOCOL);

    /* An unknown type claiming a 0xffff-byte payload: rejected on the
     * type, never read (this once overflowed a 4-byte buffer). */
    const uint8_t huge[] = {0x99, 0x00, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 7, 8};
    assert_int_equal(run(&f, huge, sizeof huge, &e, &result), FPD_ERR_PROTOCOL);
}

static void test_early_close(void **state)
{
    (void)state;
    uint8_t r[8];
    frame_u32(r, FPD_EV_RESULT, 0);
    struct fake_fpd f = {0};
    struct events e = {0, 0, 0};
    uint32_t result = 0;
    /* Half a frame, then the connection closes. */
    assert_int_equal(run(&f, r, 5, &e, &result), FPD_ERR_IO);
    assert_int_equal(run(&f, NULL, 0, &e, &result), FPD_ERR_IO);
}

static void test_hung_fpd_times_out(void **state)
{
    (void)state;
    struct fake_fpd f = {0};
    f.hang = 1;
    struct events e = {0, 0, 0};
    uint32_t result = 0;
    assert_int_equal(run(&f, NULL, 0, &e, &result), FPD_ERR_TIMEOUT);
}

static void test_no_timeout_waits_for_fpd(void **state)
{
    (void)state;
    /* With no timeout the client outlasts its own grace period (300 ms in
     * the test build) and still takes fpd's late answer. */
    uint8_t r[8];
    size_t n = frame_u32(r, FPD_EV_RESULT, FPD_RESULT_MATCH);
    struct fake_fpd f = {0};
    f.delay_ms = 600;
    fake_fpd_start(&f, r, n);
    struct fpd_verify_opts o = {.socket_path = f.path, .uid = 1, .timeout_ms = FPD_TIMEOUT_NONE, .max_tries = 1};
    uint32_t result = 99;
    assert_int_equal(fpd_verify(&o, NULL, NULL, &result), FPD_OK);
    assert_int_equal(result, FPD_RESULT_MATCH);
    fake_fpd_stop(&f);
}

static void test_connect_and_argument_errors(void **state)
{
    (void)state;
    uint32_t result = 0;
    struct fpd_verify_opts o = {.socket_path = "/nonexistent/fpd.sock", .uid = 1, .timeout_ms = 10, .max_tries = 1};
    assert_int_equal(fpd_verify(&o, NULL, NULL, &result), FPD_ERR_CONNECT);
    assert_non_null(strstr(fpd_last_error(), "/nonexistent/fpd.sock"));

    char longpath[200];
    memset(longpath, 'a', sizeof longpath - 1);
    longpath[sizeof longpath - 1] = '\0';
    o.socket_path = longpath;
    assert_int_equal(fpd_verify(&o, NULL, NULL, &result), FPD_ERR_ARG);
    o.socket_path = "";
    assert_int_equal(fpd_verify(&o, NULL, NULL, &result), FPD_ERR_ARG);
    assert_int_equal(fpd_verify(NULL, NULL, NULL, &result), FPD_ERR_ARG);
    o.socket_path = "/x";
    assert_int_equal(fpd_verify(&o, NULL, NULL, NULL), FPD_ERR_ARG);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_match_with_events),
        cmocka_unit_test(test_results_pass_through),
        cmocka_unit_test(test_protocol_errors),
        cmocka_unit_test(test_early_close),
        cmocka_unit_test(test_hung_fpd_times_out),
        cmocka_unit_test(test_no_timeout_waits_for_fpd),
        cmocka_unit_test(test_connect_and_argument_errors),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
