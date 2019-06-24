#pragma once
#include "list.h"

enum {
    MAX_HTTP_HEADER_SIZE = 4096,
};

typedef enum http_method_t {
    INVALID_HTTP_METHOD = -1,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT,
} http_method_t;

typedef enum http_status_t {
    INVALID_HTTP_STATUS = -1,
    HTTP_STATUS_CONTINUE = 100,
    HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
    HTTP_STATUS_PROCESSING = 102,

    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_ACCEPTED = 202,
    HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_RESET_CONTENT = 205,
    HTTP_STATUS_PARTIAL_CONTENT = 206,
    HTTP_STATUS_MULTI_STATUS = 207,

    HTTP_STATUS_MULTIPLE_CHOICES = 300,
    HTTP_STATUS_MOVED_PERMANENTLY = 301,
    HTTP_STATUS_FOUND = 302,
    HTTP_STATUS_SEE_OTHER = 303,
    HTTP_STATUS_NOT_MODIFIED = 304,
    HTTP_STATUS_USE_PROXY = 305,
    HTTP_STATUS_SWITCH_PROXY = 306,
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,

    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_PAYMENT_REQUIRED = 402,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_NOT_ACCEPTABLE = 406,
    HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_STATUS_REQUEST_TIMEOUT = 408,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_GONE = 410,
    HTTP_STATUS_LENGTH_REQUIRED = 411,
    HTTP_STATUS_PRECONDITION_FAILED = 412,
    HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
    HTTP_STATUS_REQUEST_URI_TOO_LONG = 414,
    HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
    HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
    HTTP_STATUS_EXPECTATION_FAILED = 417,
    HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
    HTTP_STATUS_LOCKED = 423,
    HTTP_STATUS_FAILED_DEPENDENCY = 424,
    HTTP_STATUS_UNORDERED_COLLECTION = 425,
    HTTP_STATUS_UPGRADE_REQUIRED = 426,
    HTTP_STATUS_NO_RESPONSE = 444,
    HTTP_STATUS_RETRY_WITH = 449,
    HTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450,
    HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501,
    HTTP_STATUS_BAD_GATEWAY = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT = 504,
    HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
    HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
    HTTP_STATUS_INSUFFICIENT_STORAGE = 507,
    HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED = 509,
    HTTP_STATUS_NOT_EXTENDED = 510,
} http_status_t;

enum ws_opcode {
    WS_OPCODE_CONTINUATION_FRAME = 0,
    WS_OPCODE_TEXT = 1,
    WS_OPCODE_BINARY = 2,
    WS_OPCODE_CLOSE = 8,
    WS_OPCODE_PING = 9,
    WS_OPCODE_PONG = 10,
};

struct ws_frame {
    unsigned char fin;
    unsigned char opcode;
    unsigned char mask;
    unsigned char mask_key[4];
    int payload_len;
    char *payload_data;
};

typedef struct http_header_t {
    char *name;
    char *value;
    struct list_head link;
} http_header_t;

typedef struct http_request_t {
    void *peer;
    http_method_t method;
    char *path;
    int body_len;
    char *body;
    int full_len;
    struct list_head header_list;
    struct list_head link;
} http_request_t;

typedef struct http_response_t {
    void *peer;
    http_status_t status;
    int body_len;
    char *body;
    int full_len;
    struct list_head header_list;
} http_response_t;

const char *http_strstatus(http_status_t status);
const char *http_strmethod(http_method_t method);
const char *http_get_header(struct list_head *list, const char *name);
http_request_t *http_request_new(void *peer);
void http_request_del(http_request_t *req);
http_request_t *http_parse_request(void *peer, const char *p, const char *const pend);

http_response_t *http_response_new(void *peer);
void http_response_del(http_response_t *response);
http_response_t *http_parse_response(void *peer, const char *p, const char *const pend);
