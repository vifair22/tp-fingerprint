/*
 * The wire protocol between fpd and its clients, as far as pam_fpd.so
 * needs it. fpd's side is internal/proto; a Go test reads this file and
 * checks every constant against it, so the two cannot drift.
 *
 * A frame is a little-endian u16 type, a u16 payload length, then the
 * payload. pam_fpd sends one VERIFY and reads PROMPT, RETRY and RESULT
 * frames until a RESULT; each has a fixed payload size, so the module
 * never parses anything of variable length.
 */
#ifndef FPD_PROTO_H
#define FPD_PROTO_H

#define FPD_SOCKET_PATH "/run/fpd/fpd.sock"

#define FPD_FRAME_HEADER_LEN 4U

/* Requests (client to fpd) */
#define FPD_REQ_VERIFY 0x0001U
#define FPD_REQ_VERIFY_LEN 12U /* u32 uid, u32 timeout_ms, u32 max_tries */
/* timeout_ms meaning "wait until the caller hangs up" (the lock screen) */
#define FPD_TIMEOUT_NONE 0xFFFFFFFFU

/* Events (fpd to client) */
#define FPD_EV_PROMPT 0x0081U
#define FPD_EV_PROMPT_LEN 0U
#define FPD_EV_RETRY 0x0082U
#define FPD_EV_RETRY_LEN 4U /* u32 reason */
#define FPD_EV_RESULT 0x0083U
#define FPD_EV_RESULT_LEN 4U /* u32 result */

/* RETRY reasons */
#define FPD_RETRY_SCAN 1U     /* the scan was not usable */
#define FPD_RETRY_NO_MATCH 2U /* the finger did not match; tries remain */

/* RESULT codes */
#define FPD_RESULT_MATCH 0U
#define FPD_RESULT_NO_MATCH 1U
#define FPD_RESULT_NOT_ENROLLED 2U
#define FPD_RESULT_UNAVAILABLE 3U
#define FPD_RESULT_BUSY 4U
#define FPD_RESULT_TIMEOUT 5U
#define FPD_RESULT_DENIED 6U
#define FPD_RESULT_BAD_REQUEST 7U
#define FPD_RESULT_ERROR 8U
#define FPD_RESULT_CANCELLED 9U
#define FPD_RESULT_EXISTS 10U
#define FPD_RESULT_REMOTE 11U
#define FPD_RESULT_LOCKED_OUT 12U /* too many non-matching fingers lately */

#endif /* FPD_PROTO_H */
