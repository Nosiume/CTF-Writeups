#include "http_handler.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_BUFFER_SIZE 16384
#define BUF_STACK_SIZE 128
#define DELAY 5000
#define FILE_READ_CHUNK_SIZE 4096

http_request_t current_request = { 0 };
static __thread int last_client_fd = -1;


static const char* get_content_type(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".css")  == 0) return "text/css";
    if (strcmp(ext, ".js")   == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png")  == 0) return "image/png";
    if (strcmp(ext, ".jpg")  == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".svg")  == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico")  == 0) return "image/x-icon";
    if (strcmp(ext, ".txt")  == 0) return "text/plain";
    return "application/octet-stream";
}

static bool send_all(int fd, const void* data, size_t length) {
    const char* bytes = data;

    while (length > 0) {
        ssize_t sent = send(fd, bytes, length, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (sent == 0) {
            return false;
        }

        bytes += sent;
        length -= (size_t)sent;
    }

    return true;
}

static bool send_response_header(int fd, int status, const char* status_text,
                                 const char* content_type, size_t body_len,
                                 bool keep_alive) {
    char headers[512];
    int hlen = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        status, status_text, content_type, body_len,
        keep_alive ? "keep-alive" : "close");

    if (hlen < 0 || (size_t)hlen >= sizeof(headers)) {
        return false;
    }

    return send_all(fd, headers, (size_t)hlen);
}

static bool send_response(int fd, int status, const char* status_text,
                          const char* content_type, const char* body,
                          bool keep_alive) {
    size_t body_len = strlen(body);

    if (!send_response_header(fd, status, status_text, content_type, body_len,
                              keep_alive)) {
        return false;
    }

    return send_all(fd, body, body_len);
}

static bool read_file_contents(int file_fd, size_t initial_capacity,
                               char** out_data, size_t* out_length) {
    size_t capacity = initial_capacity > 0 ? initial_capacity : FILE_READ_CHUNK_SIZE;
    size_t length = 0;
    char* data = malloc(capacity);

    if (data == NULL) {
        return false;
    }

    while (true) {
        ssize_t received;

        if (length == capacity) {
            size_t new_capacity;
            char* resized;

            if (capacity > SIZE_MAX - FILE_READ_CHUNK_SIZE) {
                free(data);
                return false;
            }

            new_capacity = capacity + FILE_READ_CHUNK_SIZE;
            resized = realloc(data, new_capacity);
            if (resized == NULL) {
                free(data);
                return false;
            }

            data = resized;
            capacity = new_capacity;
        }

        received = read(file_fd, data + length, capacity - length);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }

            free(data);
            return false;
        }

        if (received == 0) {
            *out_data = data;
            *out_length = length;
            return true;
        }

        length += (size_t)received;
    }
}

static const char* resolve_relative_path(const char* endpoint) {
    if (strcmp(endpoint, "/") == 0) {
        return "index.html";
    }

    if (endpoint[0] == '/') {
        return endpoint + 1;
    }

    return endpoint;
}

// Can you hit this secret endpoint :O
__attribute__((noinline))
void win(void) {
    dup2(last_client_fd, 0);
    dup2(last_client_fd, 1);
    dup2(last_client_fd, 2);

    system("/bin/sh");
    pthread_exit(NULL);
}

static char* get_relative_path(client_ctx_t* ctx, const http_request_t* request) {
    char path_copy[BUF_STACK_SIZE];
    size_t checked_path_len = request->path_len;

    if (checked_path_len >= sizeof(path_copy)) {
        send_response(ctx->client_fd, 414, "URI Too Long", "text/html",
                      "<h1>Request path is too long.</h1>", false);
        return NULL;
    }

    if (strstr(request->path, "..") != NULL) {
        send_response(ctx->client_fd, 401, "Unauthorized",
                      "text/html", "<h1>GO AWAY HACKER!!!!</h1>",
                      request->keep_alive);
        return NULL;
    }

    // This program is so fast ! we need to take a breath...
    usleep(DELAY);

    strcpy(path_copy, resolve_relative_path(request->path));
    return strdup(path_copy);
}

static void serve_file(client_ctx_t* ctx, const http_request_t* request) {
    char* relative_path = get_relative_path(ctx, request);
    if (relative_path == NULL) {
        return;
    }

    const char* content_type = get_content_type(relative_path);
    size_t full_path_len = strlen(ctx->server->root_path) + strlen(relative_path) + 2;
    char* full_path = malloc(full_path_len);
    char* file_body = NULL;
    size_t file_body_len = 0;
    int file_fd = -1;
    struct stat file_stat;
    bool should_send_body = request->method != HTTP_METHOD_HEAD;

    if (full_path == NULL) {
        send_response(ctx->client_fd, 500, "Internal Server Error",
                      "text/html", "<h1>Failed to allocate response path.</h1>",
                      request->keep_alive);
        return;
    }

    snprintf(full_path, full_path_len, "%s/%s", ctx->server->root_path, relative_path);

    file_fd = open(full_path, O_RDONLY);
    if (file_fd < 0) {
        int status = errno == ENOENT ? 404 : 500;
        const char* status_text = errno == ENOENT ? "Not Found" : "Internal Server Error";
        const char* body = errno == ENOENT
            ? "<h1>File not found.</h1>"
            : "<h1>Failed to open file.</h1>";

        send_response(ctx->client_fd, status, status_text, "text/html", body,
                      request->keep_alive);
        goto cleanup;
    }

    if (fstat(file_fd, &file_stat) != 0) {
        send_response(ctx->client_fd, 404, "Not Found",
                      "text/html", "<h1>File not found.</h1>",
                      request->keep_alive);
        goto cleanup;
    }

    if (S_ISDIR(file_stat.st_mode)) {
        send_response(ctx->client_fd, 404, "Not Found",
                      "text/html", "<h1>File not found.</h1>",
                      request->keep_alive);
        goto cleanup;
    }

    if (!read_file_contents(file_fd, (size_t)file_stat.st_size,
                            &file_body, &file_body_len)) {
        send_response(ctx->client_fd, 500, "Internal Server Error",
                      "text/html", "<h1>Failed to read file.</h1>",
                      request->keep_alive);
        goto cleanup;
    }

    if (!send_response_header(ctx->client_fd, 200, "OK", content_type,
                              file_body_len, request->keep_alive)) {
        goto cleanup;
    }

    if (should_send_body &&
        !send_all(ctx->client_fd, file_body, file_body_len)) {
        fprintf(stderr, "[ERROR] Failed to stream file %s: %s\n", full_path,
                strerror(errno));
    }

cleanup:
    if (file_fd >= 0) {
        close(file_fd);
    }
    free(file_body);
    free(full_path);
    free(relative_path);
}

void* client_handler(void* arg) {
    client_ctx_t* ctx = (client_ctx_t*)arg;
    char request_buffer[REQUEST_BUFFER_SIZE];
    size_t buffered_bytes = 0;
    bool keep_connection_open = true;
    
    last_client_fd = ctx->client_fd;

    while (keep_connection_open) {
        ssize_t received = recv(ctx->client_fd,
                                request_buffer + buffered_bytes,
                                sizeof(request_buffer) - buffered_bytes, 0);

        if (received == 0) {
            break;
        }

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(stderr, "[ERROR] Failed to receive request: %s\n", strerror(errno));
            break;
        }

        buffered_bytes += (size_t)received;

        while (buffered_bytes > 0) {
            http_parse_result_t parse_result = http_parse_request(&current_request, request_buffer, buffered_bytes);

            if (parse_result.state == HTTP_PARSE_INCOMPLETE) {
                if (buffered_bytes == sizeof(request_buffer)) {
                    send_response(ctx->client_fd, 413, "Payload Too Large",
                                  "text/html",
                                  "<h1>Request is too large to process.</h1>",
                                  false);
                    keep_connection_open = false;
                }
                break;
            }

            if (parse_result.state == HTTP_PARSE_ERROR) {
                fprintf(stderr, "[ERROR] Failed to parse request: %s\n",
                        parse_result.error_message);
                send_response(ctx->client_fd, 400, "Bad Request", "text/html",
                              "<h1>Malformed HTTP request.</h1>", false);
                keep_connection_open = false;
                break;
            }

            fprintf(stdout, "[INFO] Client with fd %d requested %s %s.\n",
                    ctx->client_fd, http_method_name(current_request.method), current_request.path);

            serve_file(ctx, &current_request);
            keep_connection_open = current_request.keep_alive;

            buffered_bytes -= parse_result.consumed_bytes;
            if (buffered_bytes > 0) {
                memmove(request_buffer, request_buffer + parse_result.consumed_bytes,
                        buffered_bytes);
            }

            if (!keep_connection_open) {
                break;
            }
        }
    }

    close(ctx->client_fd);
    free(ctx);
    return NULL;
}
