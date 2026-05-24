#include "server.h"
#include "http_handler.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static void*
server_listener(void* arg) {
    server_t* server = (server_t*)arg;

    if (listen(server->sock_fd, 20) != 0) {
        fprintf(stderr, "[ERROR] Failed to listen on socket: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_in client_addr;
    //TODO: implement graceful closure
    while (1) {
        socklen_t client_addr_size = sizeof(struct sockaddr_in);
        int client_fd = accept(server->sock_fd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (client_fd < 0) {
            fprintf(stderr, "[WARNING] Failed to accept client: %s\n", strerror(errno));
            continue;
        }

        char* addr = inet_ntoa((struct in_addr)client_addr.sin_addr); 
        printf("[INFO] Received connection from %s\n", addr);

        // Open client handler
        pthread_t client_thread;
        client_ctx_t* context = malloc(sizeof(client_ctx_t));
        if (context == NULL) {
            fprintf(stderr, "[WARNING] Failed to allocate client context\n");
            close(client_fd);
            continue;
        }

        context->client_fd = client_fd;
        context->server = server;

        int err = pthread_create(&client_thread, NULL, client_handler, context);
        if (err != 0) {
            fprintf(stderr, "[WARNING] Failed to create client handler thread: %s\n",
                    strerror(err));
            close(client_fd);
            free(context);
            continue;
        }

        pthread_detach(client_thread);
    }
    return NULL;
}

enum srv_err
server_init(server_t* server, int port, const char* root_path) {
    server->port = port;
    server->root_path = strdup(root_path);
    server->listener_thread = (pthread_t){0};

    if (server->root_path == NULL) {
        return SRV_SETUP_FAILURE;
    }

    //Setup socket
    server->sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server->sock_fd < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return SRV_SETUP_FAILURE;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    serv_addr.sin_port = htons(server->port);

    // Re-use addr
    if (setsockopt(server->sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return SRV_SETUP_FAILURE;
    }

    if (bind(server->sock_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return SRV_SETUP_FAILURE;
    }

    return SRV_SETUP_SUCCESS;
}

enum srv_err
server_listen(server_t* server) {
    // Create listener thread
    int err = pthread_create(&server->listener_thread, NULL, server_listener, server);
    if (err != 0) {
        fprintf(stderr, "Failed to create server thread : %s\n", strerror(err));
        return SRV_SETUP_FAILURE;
    }

    return SRV_SETUP_SUCCESS;
}
