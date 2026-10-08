/*
 * A scriptable stand-in for fpd: listens on a fresh socket, accepts one
 * connection, records the request and writes back canned bytes.
 */
#ifndef FAKE_FPD_H
#define FAKE_FPD_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

struct fake_fpd {
    char dir[64];
    char path[128];
    int listen_fd;
    pthread_t thread;
    /* script */
    const uint8_t *reply;
    size_t reply_len;
    int hang; /* accept, then send nothing until the client goes away */
    /* recorded */
    uint8_t request[64];
    size_t request_len;
};

/* Starts a fake fpd that will send reply after reading a request. */
void fake_fpd_start(struct fake_fpd *f, const uint8_t *reply, size_t reply_len);
/* Waits for it to finish and removes its socket. */
void fake_fpd_stop(struct fake_fpd *f);

/* Frame builders for scripts. */
size_t frame_u32(uint8_t *out, uint16_t type, uint32_t value);
size_t frame_empty(uint8_t *out, uint16_t type);

#endif
