/*
 * CFML HTTP Client - HTTP/HTTPS client implementation
 * Uses BSD sockets + OpenSSL for HTTPS
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cfml_http.h"
#include "cfml_variables.h"
#include "cfml_json.h"
#include "cfml_tags.h"

/* Global SSL context */
static SSL_CTX *cfml_ssl_ctx = NULL;
static cfml_http_pool_t *cfml_conn_pool = NULL;

/* Default timeouts */
#define DEFAULT_TIMEOUT         30000   /* 30 seconds */
#define DEFAULT_CONNECT_TIMEOUT 10000   /* 10 seconds */
#define DEFAULT_READ_TIMEOUT    30000   /* 30 seconds */
#define MAX_REDIRECTS           10
#define RECV_BUFFER_SIZE        8192
#define MAX_HEADER_SIZE         65536

/* HTTP method strings */
static const char *http_methods[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
};

ngx_int_t
cfml_http_init(ngx_cycle_t *cycle)
{
    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    cfml_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (cfml_ssl_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Failed to create SSL context");
        return NGX_ERROR;
    }
    
    /* Set default SSL options */
    SSL_CTX_set_options(cfml_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_default_verify_paths(cfml_ssl_ctx);
    
    /* Initialize connection pool */
    cfml_conn_pool = ngx_pcalloc(cycle->pool, sizeof(cfml_http_pool_t));
    if (cfml_conn_pool == NULL) {
        return NGX_ERROR;
    }
    
    cfml_conn_pool->pool = cycle->pool;
    cfml_conn_pool->max_connections = 100;
    cfml_conn_pool->keepalive_timeout = 60000;  /* 60 seconds */
    ngx_queue_init(&cfml_conn_pool->free_connections);
    ngx_queue_init(&cfml_conn_pool->active_connections);
    
    return NGX_OK;
}

void
cfml_http_cleanup(ngx_cycle_t *cycle)
{
    (void)cycle;
    
    if (cfml_ssl_ctx) {
        SSL_CTX_free(cfml_ssl_ctx);
        cfml_ssl_ctx = NULL;
    }
    
    EVP_cleanup();
    ERR_free_strings();
}

cfml_http_request_t *
cfml_http_request_create(ngx_pool_t *pool)
{
    cfml_http_request_t *req;
    
    req = ngx_pcalloc(pool, sizeof(cfml_http_request_t));
    if (req == NULL) {
        return NULL;
    }
    
    req->pool = pool;
    req->method = CFML_HTTP_GET;
    req->timeout = DEFAULT_TIMEOUT;
    req->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    req->read_timeout = DEFAULT_READ_TIMEOUT;
    req->redirect = 1;
    req->max_redirects = MAX_REDIRECTS;
    req->verify_ssl = 1;
    req->resolve_url = 1;
    
    /* Initialize arrays */
    req->headers = ngx_array_create(pool, 8, sizeof(cfml_http_header_t));
    req->params = ngx_array_create(pool, 8, sizeof(cfml_http_param_t));
    req->form_fields = ngx_array_create(pool, 8, sizeof(cfml_http_param_t));
    
    if (req->headers == NULL || req->params == NULL || req->form_fields == NULL) {
        return NULL;
    }
    
    /* Default user agent */
    ngx_str_set(&req->user_agent, "PALfusion/1.0 (nginx CFML module)");
    ngx_str_set(&req->charset, "UTF-8");
    
    return req;
}

ngx_int_t
cfml_http_add_header(cfml_http_request_t *req, ngx_str_t *name, ngx_str_t *value)
{
    cfml_http_header_t *header;
    
    header = ngx_array_push(req->headers);
    if (header == NULL) {
        return NGX_ERROR;
    }
    
    header->name.len = name->len;
    header->name.data = ngx_pnalloc(req->pool, name->len + 1);
    if (header->name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(header->name.data, name->data, name->len);
    header->name.data[name->len] = '\0';
    
    header->value.len = value->len;
    header->value.data = ngx_pnalloc(req->pool, value->len + 1);
    if (header->value.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(header->value.data, value->data, value->len);
    header->value.data[value->len] = '\0';
    
    return NGX_OK;
}

ngx_int_t
cfml_http_add_param(cfml_http_request_t *req, ngx_str_t *name, 
                    ngx_str_t *value, cfml_content_type_t type)
{
    cfml_http_param_t *param;
    
    param = ngx_array_push(req->params);
    if (param == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memzero(param, sizeof(cfml_http_param_t));
    
    param->name.len = name->len;
    param->name.data = ngx_pnalloc(req->pool, name->len + 1);
    ngx_memcpy(param->name.data, name->data, name->len);
    param->name.data[name->len] = '\0';
    
    param->value.len = value->len;
    param->value.data = ngx_pnalloc(req->pool, value->len + 1);
    ngx_memcpy(param->value.data, value->data, value->len);
    param->value.data[value->len] = '\0';
    
    param->type = type;
    
    return NGX_OK;
}

ngx_int_t
cfml_http_add_form_field(cfml_http_request_t *req, ngx_str_t *name, ngx_str_t *value)
{
    cfml_http_param_t *field;
    
    field = ngx_array_push(req->form_fields);
    if (field == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memzero(field, sizeof(cfml_http_param_t));
    
    field->name.len = name->len;
    field->name.data = ngx_pnalloc(req->pool, name->len + 1);
    ngx_memcpy(field->name.data, name->data, name->len);
    field->name.data[name->len] = '\0';
    
    field->value.len = value->len;
    field->value.data = ngx_pnalloc(req->pool, value->len + 1);
    ngx_memcpy(field->value.data, value->data, value->len);
    field->value.data[value->len] = '\0';
    
    field->type = CFML_CONTENT_FORM;
    
    return NGX_OK;
}

ngx_int_t
cfml_http_add_file(cfml_http_request_t *req, ngx_str_t *name,
                   ngx_str_t *filepath, ngx_str_t *content_type)
{
    cfml_http_param_t *file;
    
    file = ngx_array_push(req->form_fields);
    if (file == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memzero(file, sizeof(cfml_http_param_t));
    
    file->name.len = name->len;
    file->name.data = ngx_pnalloc(req->pool, name->len + 1);
    ngx_memcpy(file->name.data, name->data, name->len);
    
    file->filename.len = filepath->len;
    file->filename.data = ngx_pnalloc(req->pool, filepath->len + 1);
    ngx_memcpy(file->filename.data, filepath->data, filepath->len);
    
    if (content_type && content_type->len > 0) {
        file->content_type = *content_type;
    } else {
        ngx_str_set(&file->content_type, "application/octet-stream");
    }
    
    file->type = CFML_CONTENT_BINARY;
    req->multipart = 1;
    
    return NGX_OK;
}

/* Parse URL into components */
ngx_int_t
cfml_parse_url(ngx_pool_t *pool, ngx_str_t *url, cfml_parsed_url_t *parsed)
{
    u_char *p, *start, *end;
    
    ngx_memzero(parsed, sizeof(cfml_parsed_url_t));
    
    if (url == NULL || url->len == 0) {
        return NGX_ERROR;
    }
    
    p = url->data;
    end = url->data + url->len;
    
    /* Parse scheme */
    start = p;
    while (p < end && *p != ':') {
        p++;
    }
    
    if (p < end && p + 2 < end && p[1] == '/' && p[2] == '/') {
        parsed->scheme.data = start;
        parsed->scheme.len = p - start;
        p += 3;  /* Skip :// */
    } else {
        /* No scheme, assume http */
        ngx_str_set(&parsed->scheme, "http");
        p = start;
    }
    
    /* Parse userinfo@host:port */
    start = p;
    while (p < end && *p != '/' && *p != '?' && *p != '#') {
        p++;
    }
    
    {
        u_char *host_start = start;
        u_char *host_end = p;
        u_char *at, *colon;
        
        /* Check for userinfo */
        at = ngx_strlchr(host_start, host_end, '@');
        if (at) {
            parsed->userinfo.data = host_start;
            parsed->userinfo.len = at - host_start;
            host_start = at + 1;
        }
        
        /* Check for port */
        colon = NULL;
        {
            u_char *scan;
            for (scan = host_end - 1; scan >= host_start; scan--) {
                if (*scan == ':') {
                    colon = scan;
                    break;
                }
                if (*scan == ']') break;  /* IPv6 */
            }
        }
        
        if (colon && colon > host_start) {
            parsed->host.data = host_start;
            parsed->host.len = colon - host_start;
            parsed->port = ngx_atoi(colon + 1, host_end - colon - 1);
        } else {
            parsed->host.data = host_start;
            parsed->host.len = host_end - host_start;
            
            /* Default ports */
            if (parsed->scheme.len == 5 && 
                ngx_strncasecmp(parsed->scheme.data, (u_char *)"https", 5) == 0) {
                parsed->port = 443;
            } else {
                parsed->port = 80;
            }
        }
    }
    
    /* Parse path */
    if (p < end && *p == '/') {
        start = p;
        while (p < end && *p != '?' && *p != '#') {
            p++;
        }
        parsed->path.data = start;
        parsed->path.len = p - start;
    } else {
        ngx_str_set(&parsed->path, "/");
    }
    
    /* Parse query */
    if (p < end && *p == '?') {
        p++;
        start = p;
        while (p < end && *p != '#') {
            p++;
        }
        parsed->query.data = start;
        parsed->query.len = p - start;
    }
    
    /* Parse fragment */
    if (p < end && *p == '#') {
        p++;
        parsed->fragment.data = p;
        parsed->fragment.len = end - p;
    }
    
    /* Copy host to pool for null termination */
    if (parsed->host.len > 0) {
        u_char *host_copy = ngx_pnalloc(pool, parsed->host.len + 1);
        if (host_copy) {
            ngx_memcpy(host_copy, parsed->host.data, parsed->host.len);
            host_copy[parsed->host.len] = '\0';
            parsed->host.data = host_copy;
        }
    }
    
    return NGX_OK;
}

/* URL encode a string */
ngx_str_t *
cfml_url_encode(ngx_pool_t *pool, ngx_str_t *input)
{
    ngx_str_t *output;
    u_char *dst;
    size_t len = 0;
    ngx_uint_t i;
    
    /* Calculate output length */
    for (i = 0; i < input->len; i++) {
        u_char c = input->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            len++;
        } else {
            len += 3;  /* %XX */
        }
    }
    
    output = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (output == NULL) {
        return NULL;
    }
    
    output->data = ngx_pnalloc(pool, len + 1);
    if (output->data == NULL) {
        return NULL;
    }
    
    dst = output->data;
    for (i = 0; i < input->len; i++) {
        u_char c = input->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            *dst++ = c;
        } else {
            dst = ngx_sprintf(dst, "%%%02X", c);
        }
    }
    *dst = '\0';
    output->len = dst - output->data;
    
    return output;
}

/* URL decode a string */
ngx_str_t *
cfml_url_decode(ngx_pool_t *pool, ngx_str_t *input)
{
    ngx_str_t *output;
    u_char *p, *dst, *end;
    
    output = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (output == NULL) {
        return NULL;
    }
    
    output->data = ngx_pnalloc(pool, input->len + 1);
    if (output->data == NULL) {
        return NULL;
    }
    
    p = input->data;
    end = input->data + input->len;
    dst = output->data;
    
    while (p < end) {
        if (*p == '%' && p + 2 < end) {
            u_char c = 0;
            u_char h = p[1];
            u_char l = p[2];
            
            if (h >= '0' && h <= '9') c = (h - '0') << 4;
            else if (h >= 'A' && h <= 'F') c = (h - 'A' + 10) << 4;
            else if (h >= 'a' && h <= 'f') c = (h - 'a' + 10) << 4;
            
            if (l >= '0' && l <= '9') c |= l - '0';
            else if (l >= 'A' && l <= 'F') c |= l - 'A' + 10;
            else if (l >= 'a' && l <= 'f') c |= l - 'a' + 10;
            
            *dst++ = c;
            p += 3;
        } else if (*p == '+') {
            *dst++ = ' ';
            p++;
        } else {
            *dst++ = *p++;
        }
    }
    *dst = '\0';
    output->len = dst - output->data;
    
    return output;
}

/* Build request string */
static ngx_str_t *
build_http_request(cfml_http_request_t *req, cfml_parsed_url_t *parsed)
{
    ngx_str_t *request;
    u_char *p;
    size_t len;
    cfml_http_header_t *headers;
    ngx_uint_t i;
    ngx_int_t has_host = 0, has_content_type = 0, has_content_length = 0;
    ngx_int_t has_user_agent = 0;
    
    /* Estimate size */
    len = 256;  /* Method + path + HTTP version + basic headers */
    len += parsed->path.len;
    if (parsed->query.len > 0) {
        len += 1 + parsed->query.len;
    }
    len += parsed->host.len;
    
    /* Custom headers */
    headers = req->headers->elts;
    for (i = 0; i < req->headers->nelts; i++) {
        len += headers[i].name.len + headers[i].value.len + 4;
        if (ngx_strncasecmp(headers[i].name.data, (u_char *)"Host", 4) == 0) {
            has_host = 1;
        }
        if (ngx_strncasecmp(headers[i].name.data, (u_char *)"Content-Type", 12) == 0) {
            has_content_type = 1;
        }
        if (ngx_strncasecmp(headers[i].name.data, (u_char *)"Content-Length", 14) == 0) {
            has_content_length = 1;
        }
        if (ngx_strncasecmp(headers[i].name.data, (u_char *)"User-Agent", 10) == 0) {
            has_user_agent = 1;
        }
    }
    
    len += req->body.len + 64;  /* Body + Content-Length header */
    
    request = ngx_pcalloc(req->pool, sizeof(ngx_str_t));
    if (request == NULL) {
        return NULL;
    }
    
    request->data = ngx_pnalloc(req->pool, len);
    if (request->data == NULL) {
        return NULL;
    }
    
    p = request->data;
    
    /* Request line */
    p = ngx_sprintf(p, "%s ", http_methods[req->method]);
    p = ngx_copy(p, parsed->path.data, parsed->path.len);
    if (parsed->query.len > 0) {
        *p++ = '?';
        p = ngx_copy(p, parsed->query.data, parsed->query.len);
    }
    p = ngx_sprintf(p, " HTTP/1.1\r\n");
    
    /* Host header */
    if (!has_host) {
        p = ngx_sprintf(p, "Host: %V", &parsed->host);
        if ((parsed->port != 80 && parsed->port != 443) ||
            (parsed->port == 443 && 
             ngx_strncasecmp(parsed->scheme.data, (u_char *)"https", 5) != 0)) {
            p = ngx_sprintf(p, ":%d", (int)parsed->port);
        }
        p = ngx_sprintf(p, "\r\n");
    }
    
    /* User-Agent */
    if (!has_user_agent && req->user_agent.len > 0) {
        p = ngx_sprintf(p, "User-Agent: %V\r\n", &req->user_agent);
    }
    
    /* Accept */
    p = ngx_sprintf(p, "Accept: */*\r\n");
    
    /* Connection */
    p = ngx_sprintf(p, "Connection: close\r\n");
    
    /* Custom headers */
    for (i = 0; i < req->headers->nelts; i++) {
        p = ngx_sprintf(p, "%V: %V\r\n", &headers[i].name, &headers[i].value);
    }
    
    /* Content headers for body */
    if (req->body.len > 0) {
        if (!has_content_type) {
            if (req->body_type == CFML_CONTENT_JSON) {
                p = ngx_sprintf(p, "Content-Type: application/json\r\n");
            } else if (req->body_type == CFML_CONTENT_FORM) {
                p = ngx_sprintf(p, "Content-Type: application/x-www-form-urlencoded\r\n");
            } else {
                p = ngx_sprintf(p, "Content-Type: text/plain\r\n");
            }
        }
        if (!has_content_length) {
            p = ngx_sprintf(p, "Content-Length: %uz\r\n", req->body.len);
        }
    }
    
    /* End headers */
    p = ngx_sprintf(p, "\r\n");
    
    /* Body */
    if (req->body.len > 0) {
        p = ngx_copy(p, req->body.data, req->body.len);
    }
    
    request->len = p - request->data;
    
    return request;
}

/* Parse HTTP response */
static ngx_int_t
parse_http_response(ngx_pool_t *pool, u_char *data, size_t len, 
                    cfml_http_response_t *resp)
{
    u_char *p, *start, *end, *header_end;
    u_char *body_start = NULL;
    ngx_str_t line, name, value;
    
    p = data;
    end = data + len;
    
    /* Find end of headers */
    header_end = ngx_strnstr(data, "\r\n\r\n", len);
    if (header_end == NULL) {
        header_end = ngx_strnstr(data, "\n\n", len);
        if (header_end) {
            body_start = header_end + 2;
        }
    } else {
        body_start = header_end + 4;
    }
    
    if (body_start == NULL) {
        body_start = end;
    }
    
    /* Parse status line: HTTP/1.1 200 OK */
    start = p;
    while (p < end && *p != '\r' && *p != '\n') {
        p++;
    }
    line.data = start;
    line.len = p - start;
    
    /* Skip HTTP version */
    start = line.data;
    while (start < line.data + line.len && *start != ' ') {
        start++;
    }
    
    if (start < line.data + line.len) {
        resp->http_version.data = line.data;
        resp->http_version.len = start - line.data;
        start++;  /* Skip space */
        
        /* Parse status code */
        resp->status_code = ngx_atoi(start, 3);
        start += 3;
        
        /* Skip space and get status text */
        if (*start == ' ') {
            start++;
        }
        resp->status_text.data = start;
        resp->status_text.len = line.data + line.len - start;
    }
    
    /* Initialize headers struct */
    resp->header_struct = cfml_struct_new(pool);
    resp->headers = ngx_array_create(pool, 16, sizeof(cfml_http_header_t));
    
    /* Skip to next line */
    while (p < end && (*p == '\r' || *p == '\n')) {
        p++;
    }
    
    /* Parse headers */
    while (p < body_start) {
        start = p;
        
        /* Find end of line */
        while (p < body_start && *p != '\r' && *p != '\n') {
            p++;
        }
        
        if (p == start) {
            break;  /* Empty line = end of headers */
        }
        
        line.data = start;
        line.len = p - start;
        
        /* Find colon */
        u_char *colon = ngx_strlchr(start, p, ':');
        if (colon) {
            name.data = start;
            name.len = colon - start;
            
            /* Skip colon and whitespace */
            colon++;
            while (colon < p && (*colon == ' ' || *colon == '\t')) {
                colon++;
            }
            
            value.data = colon;
            value.len = p - colon;
            
            /* Add to headers array */
            cfml_http_header_t *hdr = ngx_array_push(resp->headers);
            if (hdr) {
                hdr->name = name;
                hdr->value = value;
            }
            
            /* Add to struct (lowercase name) */
            u_char *lc_name = ngx_pnalloc(pool, name.len + 1);
            if (lc_name) {
                ngx_strlow(lc_name, name.data, name.len);
                lc_name[name.len] = '\0';
                ngx_str_t lc_str = { name.len, lc_name };
                cfml_struct_set(resp->header_struct, &lc_str, 
                               cfml_create_string(pool, &value));
            }
            
            /* Special headers */
            if (name.len == 12 && 
                ngx_strncasecmp(name.data, (u_char *)"Content-Type", 12) == 0) {
                resp->content_type = value;
            }
            if (name.len == 14 && 
                ngx_strncasecmp(name.data, (u_char *)"Content-Length", 14) == 0) {
                resp->content_length = ngx_atoi(value.data, value.len);
            }
        }
        
        /* Skip to next line */
        while (p < body_start && (*p == '\r' || *p == '\n')) {
            p++;
        }
    }
    
    /* Set body */
    if (body_start < end) {
        resp->content.data = body_start;
        resp->content.len = end - body_start;
    }
    
    /* Copy raw header */
    resp->response_header.data = data;
    resp->response_header.len = body_start - data;
    
    return NGX_OK;
}

/* Execute HTTP request */
cfml_http_response_t *
cfml_http_execute(cfml_http_request_t *req)
{
    cfml_http_response_t *resp;
    cfml_parsed_url_t parsed;
    ngx_str_t *request_str;
    struct addrinfo hints, *result;
    int sock = -1;
    SSL *ssl = NULL;
    u_char *response_buf = NULL;
    size_t response_len = 0;
    size_t response_capacity = 0;
    ssize_t bytes_read;
    ngx_msec_t start_time;
    char port_str[8];
    int is_ssl = 0;
    
    /* Create response */
    resp = ngx_pcalloc(req->pool, sizeof(cfml_http_response_t));
    if (resp == NULL) {
        return NULL;
    }
    resp->pool = req->pool;
    
    start_time = ngx_current_msec;
    
    /* Parse URL */
    if (cfml_parse_url(req->pool, &req->url, &parsed) != NGX_OK) {
        resp->error_detail.data = (u_char *)"Invalid URL";
        resp->error_detail.len = 11;
        return resp;
    }
    
    is_ssl = (parsed.scheme.len == 5 && 
              ngx_strncasecmp(parsed.scheme.data, (u_char *)"https", 5) == 0);
    
    /* Resolve hostname */
    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    ngx_snprintf((u_char *)port_str, sizeof(port_str), "%d%Z", (int)parsed.port);
    
    if (getaddrinfo((char *)parsed.host.data, port_str, &hints, &result) != 0) {
        resp->connection_failed = 1;
        resp->error_detail.data = (u_char *)"DNS resolution failed";
        resp->error_detail.len = 21;
        return resp;
    }
    
    /* Create socket and connect */
    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(result);
        resp->connection_failed = 1;
        resp->error_detail.data = (u_char *)"Socket creation failed";
        resp->error_detail.len = 22;
        return resp;
    }
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = req->connect_timeout / 1000;
    tv.tv_usec = (req->connect_timeout % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(sock, result->ai_addr, result->ai_addrlen) < 0) {
        freeaddrinfo(result);
        close(sock);
        resp->connection_failed = 1;
        resp->error_detail.data = (u_char *)"Connection failed";
        resp->error_detail.len = 17;
        return resp;
    }
    
    freeaddrinfo(result);
    
    /* SSL handshake if HTTPS */
    if (is_ssl) {
        ssl = SSL_new(cfml_ssl_ctx);
        if (ssl == NULL) {
            close(sock);
            resp->ssl_error = 1;
            resp->error_detail.data = (u_char *)"SSL context creation failed";
            resp->error_detail.len = 27;
            return resp;
        }
        
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, (char *)parsed.host.data);
        
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            resp->ssl_error = 1;
            resp->error_detail.data = (u_char *)"SSL handshake failed";
            resp->error_detail.len = 20;
            return resp;
        }
    }
    
    /* Build request */
    request_str = build_http_request(req, &parsed);
    if (request_str == NULL) {
        if (ssl) SSL_free(ssl);
        close(sock);
        resp->error_detail.data = (u_char *)"Failed to build request";
        resp->error_detail.len = 23;
        return resp;
    }
    
    /* Send request */
    if (is_ssl) {
        SSL_write(ssl, request_str->data, request_str->len);
    } else {
        send(sock, request_str->data, request_str->len, 0);
    }
    
    /* Read response */
    response_capacity = RECV_BUFFER_SIZE;
    response_buf = ngx_pnalloc(req->pool, response_capacity);
    if (response_buf == NULL) {
        if (ssl) SSL_free(ssl);
        close(sock);
        return resp;
    }
    
    /* Set read timeout */
    tv.tv_sec = req->read_timeout / 1000;
    tv.tv_usec = (req->read_timeout % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (1) {
        if (response_len + RECV_BUFFER_SIZE > response_capacity) {
            /* Grow buffer */
            size_t new_capacity = response_capacity * 2;
            u_char *new_buf = ngx_pnalloc(req->pool, new_capacity);
            if (new_buf == NULL) {
                break;
            }
            ngx_memcpy(new_buf, response_buf, response_len);
            response_buf = new_buf;
            response_capacity = new_capacity;
        }
        
        if (is_ssl) {
            bytes_read = SSL_read(ssl, response_buf + response_len, RECV_BUFFER_SIZE);
        } else {
            bytes_read = recv(sock, response_buf + response_len, RECV_BUFFER_SIZE, 0);
        }
        
        if (bytes_read <= 0) {
            break;
        }
        
        response_len += bytes_read;
    }
    
    /* Cleanup connection */
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(sock);
    
    /* Parse response */
    if (response_len > 0) {
        parse_http_response(req->pool, response_buf, response_len, resp);
        resp->succeeded = (resp->status_code >= 200 && resp->status_code < 400);
    }
    
    resp->response_time = ngx_current_msec - start_time;
    resp->final_url = req->url;
    
    return resp;
}

/* Quick GET request */
cfml_http_response_t *
cfml_http_get(ngx_pool_t *pool, ngx_str_t *url)
{
    cfml_http_request_t *req;
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NULL;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_GET;
    
    return cfml_http_execute(req);
}

/* Quick POST request */
cfml_http_response_t *
cfml_http_post(ngx_pool_t *pool, ngx_str_t *url, ngx_str_t *body, ngx_str_t *content_type)
{
    cfml_http_request_t *req;
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NULL;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_POST;
    
    if (body) {
        req->body = *body;
    }
    
    if (content_type && content_type->len > 0) {
        cfml_http_add_header(req, &(ngx_str_t)ngx_string("Content-Type"), content_type);
    }
    
    return cfml_http_execute(req);
}

/* POST with JSON body */
cfml_http_response_t *
cfml_http_post_json(ngx_pool_t *pool, ngx_str_t *url, cfml_value_t *json_data)
{
    cfml_http_request_t *req;
    ngx_str_t *json_str;
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NULL;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_POST;
    req->body_type = CFML_CONTENT_JSON;
    
    json_str = cfml_json_serialize(pool, json_data);
    if (json_str) {
        req->body = *json_str;
    }
    
    return cfml_http_execute(req);
}

/* Convert response to CFML struct */
cfml_struct_t *
cfml_http_response_to_struct(ngx_pool_t *pool, cfml_http_response_t *resp)
{
    cfml_struct_t *result;
    ngx_str_t key;
    
    result = cfml_struct_new(pool);
    if (result == NULL) {
        return NULL;
    }
    
    /* Status code */
    ngx_str_set(&key, "statuscode");
    cfml_struct_set(result, &key, cfml_create_integer(pool, resp->status_code));
    
    /* Status text */
    ngx_str_set(&key, "statustext");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->status_text));
    
    /* Headers as struct */
    ngx_str_set(&key, "responseheader");
    {
        cfml_value_t *hdr_val = ngx_pcalloc(pool, sizeof(cfml_value_t));
        if (hdr_val) {
            hdr_val->type = CFML_TYPE_STRUCT;
            hdr_val->data.structure = resp->header_struct;
            cfml_struct_set(result, &key, hdr_val);
        }
    }
    
    /* File content (body) */
    ngx_str_set(&key, "filecontent");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->content));
    
    /* Mimetype */
    ngx_str_set(&key, "mimetype");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->content_type));
    
    /* Charset */
    ngx_str_set(&key, "charset");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->charset));
    
    /* HTTP version */
    ngx_str_set(&key, "http_version");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->http_version));
    
    /* Error detail */
    ngx_str_set(&key, "errordetail");
    cfml_struct_set(result, &key, cfml_create_string(pool, &resp->error_detail));
    
    /* Succeeded */
    ngx_str_set(&key, "succeeded");
    cfml_struct_set(result, &key, cfml_create_boolean(pool, resp->succeeded));
    
    return result;
}

/* Async execute placeholder - full implementation would need event loop */
ngx_int_t
cfml_http_execute_async(cfml_http_request_t *req,
                        void (*callback)(cfml_http_response_t *resp, void *data),
                        void *callback_data)
{
    /* For now, execute synchronously and call callback */
    cfml_http_response_t *resp = cfml_http_execute(req);
    if (callback) {
        callback(resp, callback_data);
    }
    return NGX_OK;
}

/* Build query string from struct */
ngx_str_t *
cfml_build_query_string(ngx_pool_t *pool, cfml_struct_t *params)
{
    ngx_str_t *result;
    cfml_struct_entry_t *entries;
    ngx_uint_t i;
    size_t len = 0;
    u_char *p;
    
    if (params == NULL || params->entries->nelts == 0) {
        result = ngx_pcalloc(pool, sizeof(ngx_str_t));
        return result;
    }
    
    entries = params->entries->elts;
    
    /* Calculate length */
    for (i = 0; i < params->entries->nelts; i++) {
        len += entries[i].key.len * 3 + 1;  /* key (encoded) + = */
        if (entries[i].value && entries[i].value->type == CFML_TYPE_STRING) {
            len += entries[i].value->data.string.len * 3;  /* value (encoded) */
        }
        len += 1;  /* & */
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->data = ngx_pnalloc(pool, len);
    if (result->data == NULL) {
        return NULL;
    }
    
    p = result->data;
    for (i = 0; i < params->entries->nelts; i++) {
        if (i > 0) {
            *p++ = '&';
        }
        
        ngx_str_t *encoded = cfml_url_encode(pool, &entries[i].key);
        if (encoded) {
            p = ngx_copy(p, encoded->data, encoded->len);
        }
        
        *p++ = '=';
        
        if (entries[i].value && entries[i].value->type == CFML_TYPE_STRING) {
            encoded = cfml_url_encode(pool, &entries[i].value->data.string);
            if (encoded) {
                p = ngx_copy(p, encoded->data, encoded->len);
            }
        }
    }
    
    result->len = p - result->data;
    return result;
}

/* Parse query string to struct */
cfml_struct_t *
cfml_parse_query_string(ngx_pool_t *pool, ngx_str_t *query)
{
    cfml_struct_t *result;
    u_char *p, *end, *key_start, *value_start;
    ngx_str_t key, value;
    
    result = cfml_struct_new(pool);
    if (result == NULL) {
        return NULL;
    }
    
    if (query == NULL || query->len == 0) {
        return result;
    }
    
    p = query->data;
    end = query->data + query->len;
    
    while (p < end) {
        key_start = p;
        
        /* Find = or & */
        while (p < end && *p != '=' && *p != '&') {
            p++;
        }
        
        key.data = key_start;
        key.len = p - key_start;
        
        if (p < end && *p == '=') {
            p++;
            value_start = p;
            
            /* Find & or end */
            while (p < end && *p != '&') {
                p++;
            }
            
            value.data = value_start;
            value.len = p - value_start;
        } else {
            value.data = (u_char *)"";
            value.len = 0;
        }
        
        if (key.len > 0) {
            ngx_str_t *decoded_key = cfml_url_decode(pool, &key);
            ngx_str_t *decoded_value = cfml_url_decode(pool, &value);
            
            if (decoded_key && decoded_value) {
                cfml_struct_set(result, decoded_key, 
                               cfml_create_string(pool, decoded_value));
            }
        }
        
        if (p < end && *p == '&') {
            p++;
        }
    }
    
    return result;
}

/* cfhttp tag handler */
ngx_int_t
cfml_tag_http(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    cfml_struct_t *result_struct;
    ngx_str_t result_var;
    ngx_str_t *attr_val;
    
    req = cfml_http_request_create(ctx->pool);
    if (req == NULL) {
        return NGX_ERROR;
    }
    
    /* Parse attributes using tag attribute API */
    attr_val = cfml_get_tag_attribute(node, "url");
    if (attr_val) {
        req->url = *attr_val;
    }
    
    attr_val = cfml_get_tag_attribute(node, "method");
    if (attr_val) {
        if (ngx_strncasecmp(attr_val->data, (u_char *)"POST", 4) == 0) {
            req->method = CFML_HTTP_POST;
        } else if (ngx_strncasecmp(attr_val->data, (u_char *)"PUT", 3) == 0) {
            req->method = CFML_HTTP_PUT;
        } else if (ngx_strncasecmp(attr_val->data, (u_char *)"DELETE", 6) == 0) {
            req->method = CFML_HTTP_DELETE;
        } else if (ngx_strncasecmp(attr_val->data, (u_char *)"HEAD", 4) == 0) {
            req->method = CFML_HTTP_HEAD;
        } else if (ngx_strncasecmp(attr_val->data, (u_char *)"PATCH", 5) == 0) {
            req->method = CFML_HTTP_PATCH;
        } else if (ngx_strncasecmp(attr_val->data, (u_char *)"OPTIONS", 7) == 0) {
            req->method = CFML_HTTP_OPTIONS;
        }
    }
    
    attr_val = cfml_get_tag_attribute(node, "timeout");
    if (attr_val) {
        req->timeout = ngx_atoi(attr_val->data, attr_val->len) * 1000;
    }
    
    attr_val = cfml_get_tag_attribute(node, "username");
    if (attr_val) {
        req->username = *attr_val;
    }
    
    attr_val = cfml_get_tag_attribute(node, "password");
    if (attr_val) {
        req->password = *attr_val;
    }
    
    attr_val = cfml_get_tag_attribute(node, "useragent");
    if (attr_val) {
        req->user_agent = *attr_val;
    }
    
    attr_val = cfml_get_tag_attribute(node, "result");
    if (attr_val) {
        result_var = *attr_val;
    } else {
        ngx_str_set(&result_var, "cfhttp");
    }
    
    /* TODO: Process child cfhttpparam tags */
    
    /* Execute request */
    resp = cfml_http_execute(req);
    
    /* Convert to struct and set variable */
    result_struct = cfml_http_response_to_struct(ctx->pool, resp);
    if (result_struct) {
        cfml_value_t *result_val = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
        if (result_val) {
            result_val->type = CFML_TYPE_STRUCT;
            result_val->data.structure = result_struct;
            cfml_set_variable(ctx, &result_var, result_val);
        }
    }
    
    return NGX_OK;
}

/* cfhttpparam tag handler */
ngx_int_t
cfml_tag_httpparam(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    /* This should be processed as part of cfhttp */
    (void)ctx;
    (void)node;
    return NGX_OK;
}

/* HTTPRequest function */
cfml_value_t *
cfml_func_httprequest(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    cfml_struct_t *options;
    cfml_value_t *result;
    ngx_str_t key;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    req = cfml_http_request_create(ctx->pool);
    if (req == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* First arg is URL or options struct */
    if (argv[0]->type == CFML_TYPE_STRING) {
        req->url = argv[0]->data.string;
        
        /* Second arg might be options struct */
        if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRUCT) {
            options = argv[1]->data.structure;
            
            ngx_str_set(&key, "method");
            cfml_value_t *method = cfml_struct_get(options, &key);
            if (method && method->type == CFML_TYPE_STRING) {
                if (ngx_strncasecmp(method->data.string.data, (u_char *)"POST", 4) == 0) {
                    req->method = CFML_HTTP_POST;
                }
                /* ... other methods */
            }
            
            ngx_str_set(&key, "body");
            cfml_value_t *body = cfml_struct_get(options, &key);
            if (body && body->type == CFML_TYPE_STRING) {
                req->body = body->data.string;
            }
            
            ngx_str_set(&key, "headers");
            cfml_value_t *headers = cfml_struct_get(options, &key);
            if (headers && headers->type == CFML_TYPE_STRUCT) {
                cfml_struct_entry_t *entries = headers->data.structure->entries->elts;
                ngx_uint_t i;
                for (i = 0; i < headers->data.structure->entries->nelts; i++) {
                    if (entries[i].value->type == CFML_TYPE_STRING) {
                        cfml_http_add_header(req, &entries[i].key, 
                                           &entries[i].value->data.string);
                    }
                }
            }
            
            ngx_str_set(&key, "timeout");
            cfml_value_t *timeout = cfml_struct_get(options, &key);
            if (timeout && timeout->type == CFML_TYPE_INTEGER) {
                req->timeout = timeout->data.integer * 1000;
            }
        }
    } else if (argv[0]->type == CFML_TYPE_STRUCT) {
        options = argv[0]->data.structure;
        
        ngx_str_set(&key, "url");
        cfml_value_t *url = cfml_struct_get(options, &key);
        if (url && url->type == CFML_TYPE_STRING) {
            req->url = url->data.string;
        }
        
        /* ... parse other options */
    }
    
    /* Execute request */
    resp = cfml_http_execute(req);
    
    /* Return as struct */
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    result->type = CFML_TYPE_STRUCT;
    result->data.structure = cfml_http_response_to_struct(ctx->pool, resp);
    
    return result;
}

/* HTTPResponse function - not commonly needed, stub */
cfml_value_t *
cfml_func_httpresponse(cfml_context_t *ctx, ngx_array_t *args)
{
    (void)args;
    return cfml_create_struct(ctx->pool);
}
