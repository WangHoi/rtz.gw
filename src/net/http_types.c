#include "http_types.h"
#include "log.h"
#include <strings.h>
#include <stdlib.h>
#include <string.h>

static int http_parse_header(struct list_head *list,
                             const char *p, const char *const pend,
                             char **out_body, int *out_body_len,
                             const char **pp);
static int http_parse_url(const char *p, const char *const pend, struct http_request_t *req, const char **pp);
static void http_consume_while_spaces(const char *p, const char *const pend, const char **pp);
static void http_consume_line_end(const char *p, const char *const pend, const char **pp);
static int http_parse_request_line(const char *p, const char *const pend,
                                   struct http_request_t *req, const char **pp);

const char *http_strstatus(http_status_t status)
{
    switch (status) {
    case HTTP_STATUS_CONTINUE:
        return "Continue";
    case HTTP_STATUS_SWITCHING_PROTOCOLS:
        return "Switching Protocols";
    case HTTP_STATUS_PROCESSING:
        return "Processing";
    case HTTP_STATUS_OK:
        return "OK";
    case HTTP_STATUS_CREATED:
        return "Created";
    case HTTP_STATUS_ACCEPTED:
        return "Accepted";
    case HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION:
        return "Non-authoritative Information";
    case HTTP_STATUS_NO_CONTENT:
        return "No Content";
    case HTTP_STATUS_RESET_CONTENT:
        return "Reset Content";
    case HTTP_STATUS_PARTIAL_CONTENT:
        return "Partial Content";
    case HTTP_STATUS_MULTI_STATUS:
        return "Multi-Status";
    case HTTP_STATUS_MULTIPLE_CHOICES:
        return "Already Reported";
    case HTTP_STATUS_MOVED_PERMANENTLY:
        return "Moved Permanently";
    case HTTP_STATUS_FOUND:
        return "Found";
    case HTTP_STATUS_SEE_OTHER:
        return "See Other";
    case HTTP_STATUS_NOT_MODIFIED:
        return "Not Modified";
    case HTTP_STATUS_USE_PROXY:
        return "Use Proxy";
    case HTTP_STATUS_SWITCH_PROXY:
        return "Switch Proxy";
    case HTTP_STATUS_TEMPORARY_REDIRECT:
        return "Temporary Redirect";
    case HTTP_STATUS_BAD_REQUEST:
        return "Bad Request";
    case HTTP_STATUS_UNAUTHORIZED:
        return "Unauthorized";
    case HTTP_STATUS_PAYMENT_REQUIRED:
        return "Payment Required";
    case HTTP_STATUS_FORBIDDEN:
        return "Forbidden";
    case HTTP_STATUS_NOT_FOUND:
        return "Not Found";
    case HTTP_STATUS_METHOD_NOT_ALLOWED:
        return "Not Allowed";
    case HTTP_STATUS_NOT_ACCEPTABLE:
        return "Not Acceptable";
    case HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED:
        return "Proxy Authentication Required";
    case HTTP_STATUS_REQUEST_TIMEOUT:
        return "Request Timeout";
    case HTTP_STATUS_CONFLICT:
        return "Conflict";
    case HTTP_STATUS_GONE:
        return "Gone";
    case HTTP_STATUS_LENGTH_REQUIRED:
        return "Length Required";
    case HTTP_STATUS_PRECONDITION_FAILED:
        return "Precondition Failed";
    case HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE:
        return "Payload Too Large";
    case HTTP_STATUS_REQUEST_URI_TOO_LONG:
        return "Request-URI Too Long";
    case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
        return "Unsupported Media Type";
    case HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE:
        return "Requested Range Not Satisfiable";
    case HTTP_STATUS_EXPECTATION_FAILED:
        return "Expectation Failed";
    case HTTP_STATUS_UNPROCESSABLE_ENTITY:
        return "Unprocessable Entity";
    case HTTP_STATUS_LOCKED:
        return "Locked";
    case HTTP_STATUS_FAILED_DEPENDENCY:
        return "Failed Dependency";
    case HTTP_STATUS_UNORDERED_COLLECTION:
        return "Unordered Collection";
    case HTTP_STATUS_UPGRADE_REQUIRED:
        return "Upgrade Required";
    case HTTP_STATUS_NO_RESPONSE:
        return "No Response";
    case HTTP_STATUS_RETRY_WITH:
        return "Retry With";
    case HTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS:
        return "Blocked By Windows Parental Controls";
    case HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS:
        return "Unavailable For Legal Reasons";
    case HTTP_STATUS_INTERNAL_SERVER_ERROR:
        return "Internal Server Error";
    case HTTP_STATUS_NOT_IMPLEMENTED:
        return "Not Implemented";
    case HTTP_STATUS_BAD_GATEWAY:
        return "Bad Gateway";
    case HTTP_STATUS_SERVICE_UNAVAILABLE:
        return "Service Unavailable";
    case HTTP_STATUS_GATEWAY_TIMEOUT:
        return "Gateway Timeout";
    case HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED:
        return "HTTP Version Not Supported";
    case HTTP_STATUS_VARIANT_ALSO_NEGOTIATES:
        return "Variant Also Negotiates";
    case HTTP_STATUS_INSUFFICIENT_STORAGE:
        return "Insufficient Storage";
    case HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED:
        return "Bandwidth Limit Exceeded";
    case HTTP_STATUS_NOT_EXTENDED:
        return "Not Extended";
    default:
        return "";
    }
}

const char *http_strmethod(http_method_t method)
{
    switch (method) {
    case HTTP_METHOD_HEAD:
        return "HEAD";
    case HTTP_METHOD_GET:
        return "GET";
    case HTTP_METHOD_POST:
        return "POST";
    case HTTP_METHOD_PUT:
        return "PUT";
    case HTTP_METHOD_DELETE:
        return "DELETE";
    case HTTP_METHOD_OPTIONS:
        return "OPTIONS";
    case HTTP_METHOD_TRACE:
        return "TRACE";
    case HTTP_METHOD_CONNECT:
        return "CONNECT";
    default:
        return "";
    }
}

const char *http_get_header(struct list_head *list, const char *name)
{
    http_header_t *h;
    list_for_each_entry(h, list, link) {
        if (!strcasecmp(h->name, name))
            return h->value;
    }
    return NULL;
}

http_request_t *http_request_new(void *peer)
{
    struct http_request_t *req;
    req = malloc(sizeof(http_request_t));
    if (req == NULL)
        return NULL;
    memset(req, 0, sizeof(http_request_t));
    req->peer = peer;
    req->method = INVALID_HTTP_METHOD;
    req->path = NULL;
    req->body = NULL;
    req->body_len = 0;
    INIT_LIST_HEAD(&req->header_list);
    INIT_LIST_HEAD(&req->link);
    return req;
}

void http_request_del(http_request_t *req)
{
    if (!req)
        return;
    http_header_t *h, *tmp;
    list_for_each_entry_safe(h, tmp, &req->header_list, link) {
        free(h->name);
        free(h->value);
        free(h);
    }
    INIT_LIST_HEAD(&req->header_list);
    if (req->path)
        free(req->path);
    if (req->body)
        free(req->body);
    free(req);
}

http_request_t *http_parse_request(void *peer, const char *p, const char *const pend)
{
    struct http_request_t *req;
    int ret;
    req = http_request_new(peer);
    if (!req)
        return NULL;
    ret = http_parse_request_line(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    do {
        ret = http_parse_header(&req->header_list, p, pend, &req->body, &req->body_len, &p);
    } while (ret == 0);
    http_consume_line_end(p, pend, &p);
    if (p < pend) {
        char *unparsed = malloc(pend - p + 1);
        if (unparsed) {
            memcpy(unparsed, p, pend - p);
            unparsed[pend - p] = '\0';
            LLOG(LL_ERROR, "parse error, remain '%s'", unparsed);
        } else {
            LLOG(LL_ERROR, "parse error, remain %zu characters", pend - p);
        }
        goto err_out;
    }
    return req;
err_out:
    if (req)
        http_request_del(req);
    return NULL;
}

int http_parse_header(struct list_head *list,
                      const char *p, const char *const pend,
                      char **out_body, int *out_body_len, const char **pp)
{
    http_header_t *hdr = NULL;
    char *hdr_name = NULL;
    char *hdr_value = NULL;
    char *tmp;
    int ret;
    ret = sscanf(p, "%m[^: \r\n]", &hdr_name);
    if (ret > 0) {
        p += strlen(hdr_name);
    } else {
        ret = -1;
        goto err_out;
    }
    http_consume_while_spaces(p, pend, &p);
    if (*p++ != ':') {
        ret = -1;
        goto err_out;
    }
    http_consume_while_spaces(p, pend, &p);
    ret = sscanf(p, "%m[^\r\n]", &hdr_value);
    if (ret > 0) {
        p += strlen(hdr_value);
    } else {
        ret = -1;
        goto err_out;
    }
    http_consume_line_end(p, pend, &p);
    while (p < pend && (*p == ' ' || *p == '\t')) {
        http_consume_while_spaces(p, pend, &p);
        char *hdr_value_cont = NULL;
        ret = sscanf(p, "%m[^\r\n]", &hdr_value_cont);
        if (ret > 0) {
            p += strlen(hdr_value_cont);
            int value_len = strlen(hdr_value);
            int value_cont_len = strlen(hdr_value_cont);
            tmp = realloc(hdr_value, value_len + value_cont_len + 1);
            if (tmp)
                hdr_value = tmp;
            else
                goto err_out;
            strcpy(hdr_value + value_len, hdr_value_cont);
            free(hdr_value_cont);
            http_consume_while_spaces(p, pend, &p);
        } else {
            free(hdr_value_cont);
            ret = -1;
            goto err_out;
        }
    }
    if (strcasecmp(hdr_name, "Content-Length") == 0) {
        char *end_ptr = NULL;
        unsigned long len = strtoul(hdr_value, &end_ptr, 10);
        if (*end_ptr == '\0') {
            *out_body_len = len;
            *out_body = realloc(*out_body, len);
        } else {
            ret = -1;
            goto err_out;
        }
    }
    ret = 0;
    hdr = malloc(sizeof(http_header_t));
    hdr->name = hdr_name;
    hdr->value = hdr_value;
    hdr_name = NULL;
    hdr_value = NULL;
    list_add_tail(&hdr->link, list);
err_out:
    free(hdr_name);
    free(hdr_value);
    *pp = p;
    return ret;
}

int http_parse_method(const char *p, const char *const pend,
                      struct http_request_t *req, const char **pp)
{
    char method[10];
    int ret;
    ret = sscanf(p, "%9[A-Z]", method);
    if (ret > 0) {
        if (strcmp(method, "HEAD") == 0)
            req->method = HTTP_METHOD_HEAD;
        else if (strcmp(method, "GET") == 0)
            req->method = HTTP_METHOD_GET;
        else if (strcmp(method, "POST") == 0)
            req->method = HTTP_METHOD_POST;
        else if (strcmp(method, "PUT") == 0)
            req->method = HTTP_METHOD_PUT;
        else if (strcmp(method, "DELETE") == 0)
            req->method = HTTP_METHOD_DELETE;
        else if (strcmp(method, "OPTIONS") == 0)
            req->method = HTTP_METHOD_OPTIONS;
        else if (strcmp(method, "TRACE") == 0)
            req->method = HTTP_METHOD_TRACE;
        else if (strcmp(method, "CONNECT") == 0)
            req->method = HTTP_METHOD_CONNECT;
        else
            return -1;
        *pp = p + strlen(method);
        return 0;
    }
    return -1;
}

int http_parse_url(const char *p, const char *const pend, struct http_request_t *req, const char **pp)
{
    int ret = sscanf(p, "%ms", &req->path);
    if (ret > 0) {
        *pp = p + strlen(req->path);
        return 0;
    } else {
        free(req->path);
        req->path = NULL;
        return -1;
    }
}

void http_consume_while_spaces(const char *p, const char *const pend, const char **pp)
{
    while (p < pend && (*p == ' ' || *p == '\t'))
        ++p;
    *pp = p;
}

void http_consume_line_end(const char *p, const char *const pend, const char **pp)
{
    while (p < pend && *p != '\n')
        ++p;
    if (p < pend && *p == '\n')
        ++p;
    *pp = p;
}

int http_parse_request_line(const char *p, const char *const pend,
                            struct http_request_t *req, const char **pp)
{
    int ret;
    ret = http_parse_method(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    http_consume_while_spaces(p, pend, &p);
    ret = http_parse_url(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    //ret = http_parse_version(p, pend, req, pp);
    //if (ret != 0)
        //goto err_out;
    http_consume_line_end(p, pend, &p);
err_out:
    *pp = p;
    return ret;
}

int http_parse_response_line(const char *p, const char *const pend,
                             struct http_response_t *r, const char **pp)
{
    int ret;
    int status = INVALID_HTTP_STATUS;
    ret = sscanf(p, "HTTP/1.%*d %d %*s", &status);
    if (ret != 1) {
        ret = -1;
        goto err_out;
    }
    ret = 0;
    r->status = (http_status_t)status;
    http_consume_line_end(p, pend, &p);
err_out:
    *pp = p;
    return ret;
}

http_response_t *http_response_new(void *peer)
{
    struct http_response_t *r;
    r = malloc(sizeof(http_response_t));
    if (!r)
        return NULL;
    memset(r, 0, sizeof(http_response_t));
    r->status = INVALID_HTTP_STATUS;
    r->peer = peer;
    r->body = NULL;
    r->body_len = 0;
    INIT_LIST_HEAD(&r->header_list);
    return r;
}

void http_response_del(http_response_t *response)
{
    if (!response)
        return;
    http_header_t *h, *tmp;
    list_for_each_entry_safe(h, tmp, &response->header_list, link) {
        free(h->name);
        free(h->value);
        free(h);
    }
    INIT_LIST_HEAD(&response->header_list);
    if (response->body)
        free(response->body);
    free(response);
}

http_response_t *http_parse_response(void *peer, const char *p, const char *const pend)
{
    struct http_response_t *r;
    int ret;
    r = http_response_new(peer);
    if (!r)
        return NULL;
    ret = http_parse_response_line(p, pend, r, &p);
    if (ret != 0)
        goto err_out;
    do {
        ret = http_parse_header(&r->header_list, p, pend, &r->body, &r->body_len, &p);
    } while (ret == 0);
    http_consume_line_end(p, pend, &p);
    if (p < pend) {
        char *unparsed = malloc(pend - p + 1);
        if (unparsed) {
            memcpy(unparsed, p, pend - p);
            unparsed[pend - p] = '\0';
            LLOG(LL_ERROR, "parse error, remain '%s'", unparsed);
            free(unparsed);
        } else {
            LLOG(LL_ERROR, "parse error, remain %zu characters", pend - p);
        }
        goto err_out;
    }
    return r;
err_out:
    if (r)
        http_response_del(r);
    return NULL;

}
