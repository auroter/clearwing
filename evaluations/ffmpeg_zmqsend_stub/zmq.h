#ifndef CLEARWING_FFMPEG_ZMQSEND_STUB_H
#define CLEARWING_FFMPEG_ZMQSEND_STUB_H

#include <stddef.h>

#define ZMQ_REQ 3

typedef struct zmq_msg_t {
    unsigned char storage[64];
} zmq_msg_t;

void *zmq_ctx_new(void);
int zmq_ctx_destroy(void *context);
void *zmq_socket(void *context, int type);
int zmq_close(void *socket);
int zmq_connect(void *socket, const char *endpoint);
int zmq_send(void *socket, const void *buffer, size_t length, int flags);
int zmq_msg_init(zmq_msg_t *message);
int zmq_msg_recv(zmq_msg_t *message, void *socket, int flags);
size_t zmq_msg_size(const zmq_msg_t *message);
void *zmq_msg_data(zmq_msg_t *message);
int zmq_msg_close(zmq_msg_t *message);
const char *zmq_strerror(int error_number);

#endif
