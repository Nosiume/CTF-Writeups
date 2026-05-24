#include "http_parser.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

static bool is_http_whitespace(char ch) {
    return ch == ' ' || ch == '\t';
}

static bool ascii_char_equal_ignore_case(char lhs, char rhs) {
    return tolower((unsigned char)lhs) == tolower((unsigned char)rhs);
}

static bool ascii_span_equal_ignore_case(const char* lhs, size_t lhs_len,
                                         const char* rhs) {
    size_t rhs_len = strlen(rhs);

    if (lhs_len != rhs_len) {
        return false;
    }

    for (size_t i = 0; i < lhs_len; ++i) {
        if (!ascii_char_equal_ignore_case(lhs[i], rhs[i])) {
            return false;
        }
    }

    return true;
}

static size_t find_crlf(const char* buffer, size_t start, size_t buffer_len) {
    for (size_t i = start; i + 1 < buffer_len; ++i) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
            return i;
        }
    }

    return SIZE_MAX;
}

static size_t find_header_terminator(const char* buffer, size_t buffer_len) {
    for (size_t i = 0; i + 3 < buffer_len; ++i) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n' &&
            buffer[i + 2] == '\r' && buffer[i + 3] == '\n') {
            return i;
        }
    }

    return SIZE_MAX;
}

static const char* trim_left(const char* start, const char* end) {
    while (start < end && is_http_whitespace(*start)) {
        ++start;
    }

    return start;
}

static const char* trim_right(const char* start, const char* end) {
    while (end > start && is_http_whitespace(*(end - 1))) {
        --end;
    }

    return end;
}

static bool parse_size_value(const char* start, const char* end, size_t* value) {
    size_t parsed = 0;

    if (start == end) {
        return false;
    }

    for (const char* cursor = start; cursor < end; ++cursor) {
        if (!isdigit((unsigned char)*cursor)) {
            return false;
        }

        size_t digit = (size_t)(*cursor - '0');
        if (parsed > (SIZE_MAX - digit) / 10) {
            return false;
        }

        parsed = (parsed * 10) + digit;
    }

    *value = parsed;
    return true;
}

static bool parse_http_version(const char* start, const char* end,
                               unsigned int* major, unsigned int* minor) {
    static const char prefix[] = "HTTP/";
    size_t prefix_len = sizeof(prefix) - 1;

    if ((size_t)(end - start) <= prefix_len ||
        memcmp(start, prefix, prefix_len) != 0) {
        return false;
    }

    const char* version = start + prefix_len;
    const char* dot = memchr(version, '.', (size_t)(end - version));
    size_t parsed_major = 0;
    size_t parsed_minor = 0;

    if (dot == NULL || dot == version || dot + 1 == end) {
        return false;
    }

    if (!parse_size_value(version, dot, &parsed_major) ||
        !parse_size_value(dot + 1, end, &parsed_minor)) {
        return false;
    }

    if (parsed_major > UINT_MAX || parsed_minor > UINT_MAX) {
        return false;
    }

    *major = (unsigned int)parsed_major;
    *minor = (unsigned int)parsed_minor;
    return true;
}

static http_method_t parse_method(const char* start, size_t length) {
    if (ascii_span_equal_ignore_case(start, length, "GET")) {
        return HTTP_METHOD_GET;
    }
    if (ascii_span_equal_ignore_case(start, length, "HEAD")) {
        return HTTP_METHOD_HEAD;
    }
    if (ascii_span_equal_ignore_case(start, length, "POST")) {
        return HTTP_METHOD_POST;
    }
    if (ascii_span_equal_ignore_case(start, length, "PUT")) {
        return HTTP_METHOD_PUT;
    }
    if (ascii_span_equal_ignore_case(start, length, "DELETE")) {
        return HTTP_METHOD_DELETE;
    }
    if (ascii_span_equal_ignore_case(start, length, "OPTIONS")) {
        return HTTP_METHOD_OPTIONS;
    }
    if (ascii_span_equal_ignore_case(start, length, "PATCH")) {
        return HTTP_METHOD_PATCH;
    }
    if (ascii_span_equal_ignore_case(start, length, "TRACE")) {
        return HTTP_METHOD_TRACE;
    }

    return HTTP_METHOD_UNKNOWN;
}

static bool copy_request_path(http_request_t* request, const char* start,
                              size_t length, const char** error_message) {
    const char* path_start = start;
    const char* path_end = start + length;
    const char* query = NULL;
    const char* fragment = NULL;

    if (length == 1 && start[0] == '*') {
        *error_message = "asterisk-form requests are not supported";
        return false;
    }

    if (length >= 7 &&
        ascii_span_equal_ignore_case(start, 7, "http://")) {
        const char* authority_end = memchr(start + 7, '/', length - 7);
        if (authority_end == NULL) {
            path_start = "/";
            path_end = path_start + 1;
        } else {
            path_start = authority_end;
        }
    } else if (length >= 8 &&
               ascii_span_equal_ignore_case(start, 8, "https://")) {
        const char* authority_end = memchr(start + 8, '/', length - 8);
        if (authority_end == NULL) {
            path_start = "/";
            path_end = path_start + 1;
        } else {
            path_start = authority_end;
        }
    } else if (length == 0 || start[0] != '/') {
        *error_message = "request target must start with '/'";
        return false;
    }

    query = memchr(path_start, '?', (size_t)(path_end - path_start));
    if (query != NULL) {
        path_end = query;
    }

    fragment = memchr(path_start, '#', (size_t)(path_end - path_start));
    if (fragment != NULL) {
        path_end = fragment;
    }

    if (path_end == path_start) {
        request->path[0] = '/';
        request->path[1] = '\0';
        request->path_len = 1;
        return true;
    }

    if ((size_t)(path_end - path_start) >= HTTP_MAX_PATH_LEN) {
        *error_message = "request path is too long";
        return false;
    }

    request->path_len = (size_t)(path_end - path_start);
    memcpy(request->path, path_start, request->path_len);
    request->path[request->path_len] = '\0';
    return true;
}

static bool header_value_has_token(const char* start, const char* end,
                                   const char* token) {
    const char* cursor = start;

    while (cursor < end) {
        const char* token_start;
        const char* token_end;

        while (cursor < end &&
               (*cursor == ',' || is_http_whitespace(*cursor))) {
            ++cursor;
        }

        token_start = cursor;
        while (cursor < end && *cursor != ',') {
            ++cursor;
        }

        token_end = trim_right(token_start, cursor);
        if (token_end > token_start &&
            ascii_span_equal_ignore_case(token_start,
                                         (size_t)(token_end - token_start),
                                         token)) {
            return true;
        }
    }

    return false;
}

static bool parse_request_line(http_request_t* request, const char* buffer,
                               size_t line_end, const char** error_message) {
    const char* line_start = buffer;
    const char* line_stop = buffer + line_end;
    const char* first_space = memchr(line_start, ' ', (size_t)(line_stop - line_start));
    const char* second_space;

    if (first_space == NULL || first_space == line_start) {
        *error_message = "malformed request line";
        return false;
    }

    second_space = memchr(first_space + 1, ' ',
                          (size_t)(line_stop - (first_space + 1)));
    if (second_space == NULL || second_space == first_space + 1 ||
        second_space + 1 == line_stop) {
        *error_message = "malformed request line";
        return false;
    }

    request->method = parse_method(line_start, (size_t)(first_space - line_start));
    if (request->method == HTTP_METHOD_UNKNOWN) {
        *error_message = "unsupported HTTP method";
        return false;
    }

    if (!copy_request_path(request, first_space + 1,
                           (size_t)(second_space - (first_space + 1)),
                           error_message)) {
        return false;
    }

    if (!parse_http_version(second_space + 1, line_stop, &request->http_major,
                            &request->http_minor)) {
        *error_message = "unsupported HTTP version";
        return false;
    }

    return true;
}

static bool parse_headers(http_request_t* request, const char* buffer,
                          size_t header_end, size_t buffer_len,
                          const char** error_message) {
    bool saw_content_length = false;
    bool saw_connection_keep_alive = false;
    bool saw_connection_close = false;
    const char* cursor = buffer + find_crlf(buffer, 0, buffer_len) + 2;
    const char* headers_stop = buffer + header_end;

    while (cursor < headers_stop) {
        size_t line_start = (size_t)(cursor - buffer);
        size_t line_end = find_crlf(buffer, line_start, buffer_len);
        const char* colon;
        const char* name_end;
        const char* value_start;
        const char* value_end;

        if (line_end == SIZE_MAX || line_end > header_end) {
            *error_message = "malformed header line";
            return false;
        }

        colon = memchr(cursor, ':', line_end - line_start);
        if (colon == NULL || colon == cursor) {
            *error_message = "malformed header line";
            return false;
        }

        name_end = trim_right(cursor, colon);
        value_start = trim_left(colon + 1, buffer + line_end);
        value_end = trim_right(value_start, buffer + line_end);

        if (ascii_span_equal_ignore_case(cursor, (size_t)(name_end - cursor),
                                         "Content-Length")) {
            size_t content_length = 0;

            if (saw_content_length) {
                *error_message = "duplicate Content-Length header";
                return false;
            }

            if (!parse_size_value(value_start, value_end, &content_length)) {
                *error_message = "invalid Content-Length header";
                return false;
            }

            request->content_length = content_length;
            saw_content_length = true;
        } else if (ascii_span_equal_ignore_case(cursor, (size_t)(name_end - cursor),
                                                "Connection")) {
            saw_connection_keep_alive |=
                header_value_has_token(value_start, value_end, "keep-alive");
            saw_connection_close |=
                header_value_has_token(value_start, value_end, "close");
        } else if (ascii_span_equal_ignore_case(cursor, (size_t)(name_end - cursor),
                                                "Transfer-Encoding") &&
                   value_end > value_start) {
            *error_message = "Transfer-Encoding is not supported";
            return false;
        }

        cursor = buffer + line_end + 2;
    }

    if (request->http_major > 1 ||
        (request->http_major == 1 && request->http_minor >= 1)) {
        request->keep_alive = !saw_connection_close;
    } else {
        request->keep_alive = saw_connection_keep_alive && !saw_connection_close;
    }

    return true;
}

void http_request_reset(http_request_t* request) {
    memset(request, 0, sizeof(*request));
}

const char* http_method_name(http_method_t method) {
    switch (method) {
        case HTTP_METHOD_GET:
            return "GET";
        case HTTP_METHOD_HEAD:
            return "HEAD";
        case HTTP_METHOD_POST:
            return "POST";
        case HTTP_METHOD_PUT:
            return "PUT";
        case HTTP_METHOD_DELETE:
            return "DELETE";
        case HTTP_METHOD_OPTIONS:
            return "OPTIONS";
        case HTTP_METHOD_PATCH:
            return "PATCH";
        case HTTP_METHOD_TRACE:
            return "TRACE";
        case HTTP_METHOD_UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

http_parse_result_t http_parse_request(http_request_t* request, const char* buffer,
                                       size_t buffer_len) {
    http_parse_result_t result = {
        .state = HTTP_PARSE_INCOMPLETE,
        .consumed_bytes = 0,
        .error_message = NULL
    };
    const char* error_message = NULL;
    size_t header_end;
    size_t request_line_end;
    size_t message_size;

    if (request == NULL || buffer == NULL) {
        result.state = HTTP_PARSE_ERROR;
        result.error_message = "parser received invalid arguments";
        return result;
    }

    http_request_reset(request);

    header_end = find_header_terminator(buffer, buffer_len);
    if (header_end == SIZE_MAX) {
        return result;
    }

    request_line_end = find_crlf(buffer, 0, buffer_len);
    if (request_line_end == SIZE_MAX || request_line_end >= header_end) {
        result.state = HTTP_PARSE_ERROR;
        result.error_message = "missing request line";
        return result;
    }

    if (!parse_request_line(request, buffer, request_line_end, &error_message) ||
        !parse_headers(request, buffer, header_end, buffer_len, &error_message)) {
        result.state = HTTP_PARSE_ERROR;
        result.error_message = error_message;
        return result;
    }

    if (request->content_length > SIZE_MAX - (header_end + 4)) {
        result.state = HTTP_PARSE_ERROR;
        result.error_message = "request body is too large";
        return result;
    }

    message_size = header_end + 4 + request->content_length;
    if (buffer_len < message_size) {
        return result;
    }

    request->message_complete = true;
    result.state = HTTP_PARSE_OK;
    result.consumed_bytes = message_size;
    return result;
}
