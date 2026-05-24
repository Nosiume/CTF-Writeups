#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdbool.h>
#include <stddef.h>

#define HTTP_MAX_PATH_LEN 2048

typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_TRACE
} http_method_t;

typedef struct {
    char path[HTTP_MAX_PATH_LEN];
    size_t path_len;
    http_method_t method;
    unsigned int http_major;
    unsigned int http_minor;
    size_t content_length;
    bool keep_alive;
    bool message_complete;
} http_request_t;

typedef enum {
    HTTP_PARSE_INCOMPLETE = 0,
    HTTP_PARSE_OK,
    HTTP_PARSE_ERROR
} http_parse_state_t;

typedef struct {
    http_parse_state_t state;
    size_t consumed_bytes;
    const char* error_message;
} http_parse_result_t;

void http_request_reset(http_request_t* request);
const char* http_method_name(http_method_t method);
http_parse_result_t http_parse_request(http_request_t* request, const char* buffer,
                                       size_t buffer_len);

#endif
