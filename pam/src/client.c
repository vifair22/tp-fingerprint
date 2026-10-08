/*
 * fpd's VERIFY exchange from the client side. Everything here runs inside
 * whatever process loaded pam_fpd.so (sudo, the screen locker), so it holds
 * no state beyond one call, allocates nothing, and bounds every wait by a
 * single deadline.
 */
#include "fpd_client.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "fpd_proto.h"

static _Thread_local char last_error[256];

const char *fpd_last_error(void) { return last_error; }

__attribute__((format(printf, 1, 2))) static void set_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(last_error, sizeof last_error, fmt, ap);
    va_end(ap);
}

/* set_error with strerror(errno) appended, for failed system calls. */
#define set_error_errno(fmt, ...)                                                      \
    do {                                                                               \
        int saved_errno_ = errno;                                                      \
        char why_[128];                                                                \
        set_error(fmt ": %s", __VA_ARGS__,                                             \
                  strerror_r(saved_errno_, why_, sizeof why_));                        \
    } while (0)

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000U) + ((uint64_t)ts.tv_nsec / 1000000U);
}

static void put_u16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    put_u16(p, v & 0xffffU);
    put_u16(p + 2, v >> 16);
}

static uint32_t get_u16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }

static uint32_t get_u32(const uint8_t *p) { return get_u16(p) | get_u16(p + 2) << 16; }

static fpd_status connect_fpd(const char *path, int *out)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof addr.sun_path) {
        set_error("socket path of %zu bytes", n);
        return FPD_ERR_ARG;
    }
    memcpy(addr.sun_path, path, n + 1);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        set_error_errno("socket %s", "AF_UNIX");
        return FPD_ERR_CONNECT;
    }
    if (connect(fd, (const struct sockaddr *)&addr, sizeof addr) != 0) {
        set_error_errno("connect %s", path);
        (void)close(fd);
        return FPD_ERR_CONNECT;
    }
    *out = fd;
    return FPD_OK;
}

static fpd_status write_all(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            set_error_errno("send %s", "request");
            return FPD_ERR_IO;
        }
        buf += n;
        len -= (size_t)n;
    }
    return FPD_OK;
}

/* Reads exactly len bytes, failing with FPD_ERR_TIMEOUT at the deadline. */
static fpd_status read_exact(int fd, uint8_t *buf, size_t len, uint64_t deadline)
{
    while (len > 0) {
        uint64_t now = now_ms();
        if (now >= deadline) {
            set_error("fpd did not answer in time");
            return FPD_ERR_TIMEOUT;
        }
        uint64_t left = deadline - now;
        struct pollfd p = {.fd = fd, .events = POLLIN, .revents = 0};
        int r = poll(&p, 1, left > 60000U ? 60000 : (int)left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            set_error_errno("poll %s", "fpd socket");
            return FPD_ERR_IO;
        }
        if (r == 0)
            continue;
        ssize_t n = recv(fd, buf, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            set_error_errno("recv %s", "event");
            return FPD_ERR_IO;
        }
        if (n == 0) {
            set_error("fpd closed the connection before its result");
            return FPD_ERR_IO;
        }
        buf += n;
        len -= (size_t)n;
    }
    return FPD_OK;
}

/* The payload size an event type must have. Returns 0 (false) for a type
 * this client does not know, which is a protocol error whatever its length:
 * an earlier version returned a sentinel length instead, and an unknown
 * frame claiming exactly that length would have been read into a 4-byte
 * buffer. */
static int expected_len(uint32_t type, uint32_t *len)
{
    switch (type) {
    case FPD_EV_PROMPT:
        *len = FPD_EV_PROMPT_LEN;
        return 1;
    case FPD_EV_RETRY: /* both carry one u32 */
    case FPD_EV_RESULT:
        *len = FPD_EV_RETRY_LEN;
        return 1;
    default:
        return 0;
    }
}

static fpd_status exchange(int fd, const struct fpd_verify_opts *opts, fpd_event_cb cb,
                           void *cb_ctx, uint32_t *result)
{
    uint8_t req[FPD_FRAME_HEADER_LEN + FPD_REQ_VERIFY_LEN];
    put_u16(req, FPD_REQ_VERIFY);
    put_u16(req + 2, FPD_REQ_VERIFY_LEN);
    put_u32(req + 4, opts->uid);
    put_u32(req + 8, opts->timeout_ms);
    put_u32(req + 12, opts->max_tries);
    fpd_status st = write_all(fd, req, sizeof req);
    if (st != FPD_OK)
        return st;

    /* fpd's timeout covers the whole verify, every try included; past it
     * plus some slack, fpd itself has hung. */
    uint64_t deadline = now_ms() + (uint64_t)opts->timeout_ms + (uint64_t)FPD_GRACE_MS;
    for (;;) {
        uint8_t hdr[FPD_FRAME_HEADER_LEN];
        st = read_exact(fd, hdr, sizeof hdr, deadline);
        if (st != FPD_OK)
            return st;
        uint32_t type = get_u16(hdr);
        uint32_t len = get_u16(hdr + 2);
        uint32_t want = 0;
        if (!expected_len(type, &want) || len != want || len > 4U) {
            set_error("unexpected frame: type 0x%04x, %u bytes", (unsigned)type, (unsigned)len);
            return FPD_ERR_PROTOCOL;
        }
        uint8_t payload[4] = {0, 0, 0, 0};
        if (len > 0) {
            st = read_exact(fd, payload, len, deadline);
            if (st != FPD_OK)
                return st;
        }
        uint32_t value = len == 4 ? get_u32(payload) : 0;
        if (type == FPD_EV_RESULT) {
            *result = value;
            return FPD_OK;
        }
        if (cb != NULL)
            cb(cb_ctx, (uint16_t)type, value);
    }
}

fpd_status fpd_verify(const struct fpd_verify_opts *opts, fpd_event_cb cb, void *cb_ctx,
                      uint32_t *result)
{
    last_error[0] = '\0';
    if (opts == NULL || opts->socket_path == NULL || result == NULL) {
        set_error("missing argument");
        return FPD_ERR_ARG;
    }
    int fd = -1;
    fpd_status st = connect_fpd(opts->socket_path, &fd);
    if (st != FPD_OK)
        return st;
    st = exchange(fd, opts, cb, cb_ctx, result);
    (void)close(fd);
    return st;
}
