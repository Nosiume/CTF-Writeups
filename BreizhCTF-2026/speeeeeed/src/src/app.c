#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "server.h"

void sigpipe_handler(int unused) {
    puts("* got sigpipe ! ignoring it... this server is so fast anyways we can't bother with this crap :o");
}

int main(int argc, char** argv) {
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);

    server_t server = {0};
    if (server_init(&server, 1337, "/var/www/html") != SRV_SETUP_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (server_listen(&server) != SRV_SETUP_SUCCESS) {
        return EXIT_FAILURE;
    }

    puts("Server is listening !");
    pthread_join(server.listener_thread, NULL);
}
