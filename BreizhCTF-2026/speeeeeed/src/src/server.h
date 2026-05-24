#ifndef SERVER_H
#define SERVER_H

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

enum srv_err {
    SRV_SETUP_FAILURE,
    SRV_SETUP_SUCCESS,
    SRV_FATAL_CRASH
};

typedef struct {
    int sock_fd;
    int port;
    pthread_t listener_thread;
    const char* root_path;
} server_t;

enum srv_err server_init(server_t* srv, int port, const char* root_path);
enum srv_err server_listen(server_t* srv);

//Thread listener
static void* server_listener(void*);

#endif
