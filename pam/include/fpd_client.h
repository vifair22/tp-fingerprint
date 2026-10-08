/*
 * The client side of fpd's VERIFY exchange: connect, send one request,
 * relay PROMPT and RETRY events to a callback, return the RESULT. Kept
 * apart from the PAM glue so it can be tested against a fake fpd without
 * libpam.
 */
#ifndef FPD_CLIENT_H
#define FPD_CLIENT_H

#include <stdint.h>

/* Status codes: 0 for success, negative for failure. The deepest function
 * that fails records a message, which fpd_last_error() returns. */
typedef enum {
    FPD_OK = 0,
    FPD_ERR_ARG = -1,      /* bad options (a socket path too long) */
    FPD_ERR_CONNECT = -2,  /* fpd is not running or refused us */
    FPD_ERR_IO = -3,       /* the connection failed or closed early */
    FPD_ERR_TIMEOUT = -4,  /* fpd did not finish in time */
    FPD_ERR_PROTOCOL = -5, /* fpd sent something we do not understand */
} fpd_status;

struct fpd_verify_opts {
    const char *socket_path;
    uint32_t uid;
    uint32_t timeout_ms; /* how long fpd waits for a finger */
    uint32_t max_tries;  /* non-matching fingers allowed */
};

/* Called for each PROMPT (value 0) and RETRY (value: the reason). */
typedef void (*fpd_event_cb)(void *ctx, uint16_t type, uint32_t value);

/* Runs one VERIFY. On FPD_OK, *result holds fpd's RESULT code. The client
 * gives up FPD_GRACE_MS after the requested timeout in case fpd hangs. */
fpd_status fpd_verify(const struct fpd_verify_opts *opts, fpd_event_cb cb,
                      void *cb_ctx, uint32_t *result);

/* The message the last failure recorded on this thread. */
const char *fpd_last_error(void);

#ifndef FPD_GRACE_MS /* tests shorten it */
#define FPD_GRACE_MS 5000U
#endif

#endif /* FPD_CLIENT_H */
