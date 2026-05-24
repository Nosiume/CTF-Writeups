#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include "http_parser.h"
#include "server.h"

extern http_request_t current_request;

typedef struct {
    int client_fd;
    server_t* server;
} client_ctx_t;

void* client_handler(void* server);

#endif
