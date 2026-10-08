#include "fake_fpd.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)(v >> 8);
}

size_t frame_u32(uint8_t *out, uint16_t type, uint32_t value)
{
    put16(out, type);
    put16(out + 2, 4);
    put16(out + 4, value & 0xffffU);
    put16(out + 6, value >> 16);
    return 8;
}

size_t frame_empty(uint8_t *out, uint16_t type)
{
    put16(out, type);
    put16(out + 2, 0);
    return 4;
}

static void *serve(void *arg)
{
    struct fake_fpd *f = arg;
    int c = accept(f->listen_fd, NULL, NULL);
    if (c < 0)
        return NULL;
    /* The request is 16 bytes; read until we have them or the client stops. */
    while (f->request_len < 16) {
        ssize_t n = read(c, f->request + f->request_len, sizeof f->request - f->request_len);
        if (n <= 0)
            break;
        f->request_len += (size_t)n;
    }
    if (f->delay_ms > 0)
        (void)poll(NULL, 0, f->delay_ms);
    if (f->hang) {
        char b;
        while (read(c, &b, 1) > 0) {
        }
    } else if (f->reply_len > 0) {
        (void)write(c, f->reply, f->reply_len);
    }
    (void)close(c);
    return NULL;
}

void fake_fpd_start(struct fake_fpd *f, const uint8_t *reply, size_t reply_len)
{
    f->reply = reply;
    f->reply_len = reply_len;
    f->request_len = 0;
    snprintf(f->dir, sizeof f->dir, "/tmp/fake-fpd-XXXXXX");
    if (mkdtemp(f->dir) == NULL)
        abort();
    snprintf(f->path, sizeof f->path, "%s/fpd.sock", f->dir);
    f->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, f->path, strlen(f->path) + 1);
    if (f->listen_fd < 0 || bind(f->listen_fd, (struct sockaddr *)&a, sizeof a) != 0 ||
        listen(f->listen_fd, 1) != 0)
        abort();
    if (pthread_create(&f->thread, NULL, serve, f) != 0)
        abort();
}

void fake_fpd_stop(struct fake_fpd *f)
{
    (void)pthread_join(f->thread, NULL);
    (void)close(f->listen_fd);
    (void)unlink(f->path);
    (void)rmdir(f->dir);
}
