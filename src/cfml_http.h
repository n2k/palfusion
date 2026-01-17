/*
 * CFML HTTP Client - Modern HTTP client implementation
 * cfhttp tag support with async, connection pooling, timeouts
 */

#ifndef _CFML_HTTP_H_
#define _CFML_HTTP_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* HTTP methods */
typedef enum {
    CFML_HTTP_GET = 0,
    CFML_HTTP_POST,
    CFML_HTTP_PUT,
    CFML_HTTP_DELETE,
    CFML_HTTP_HEAD,
    CFML_HTTP_OPTIONS,
    CFML_HTTP_PATCH,
    CFML_HTTP_TRACE,
    CFML_HTTP_CONNECT
} cfml_http_method_t;

/* Content types */
typedef enum {
    CFML_CONTENT_NONE = 0,
    CFML_CONTENT_TEXT,
    CFML_CONTENT_JSON,
    CFML_CONTENT_XML,
    CFML_CONTENT_FORM,
    CFML_CONTENT_MULTIPART,
    CFML_CONTENT_BINARY
} cfml_content_type_t;

/* HTTP request parameter */
typedef struct {
    ngx_str_t               name;
    ngx_str_t               value;
    cfml_content_type_t     type;
    ngx_str_t               filename;       /* For file uploads */
    ngx_str_t               content_type;   /* MIME type for param */
} cfml_http_param_t;

/* HTTP header */
typedef struct {
    ngx_str_t               name;
    ngx_str_t               value;
} cfml_http_header_t;

/* HTTP request configuration */
typedef struct {
    ngx_str_t               url;
    cfml_http_method_t      method;
    ngx_msec_t              timeout;
    ngx_msec_t              connect_timeout;
    ngx_msec_t              read_timeout;
    
    /* Request body */
    ngx_str_t               body;
    cfml_content_type_t     body_type;
    
    /* Headers */
    ngx_array_t             *headers;       /* Array of cfml_http_header_t */
    
    /* Parameters */
    ngx_array_t             *params;        /* Array of cfml_http_param_t */
    ngx_array_t             *form_fields;   /* Array of cfml_http_param_t */
    
    /* Authentication */
    ngx_str_t               username;
    ngx_str_t               password;
    ngx_str_t               auth_type;      /* basic, digest, ntlm, bearer */
    ngx_str_t               bearer_token;
    
    /* SSL/TLS */
    unsigned                throw_on_error:1;
    unsigned                redirect:1;
    unsigned                compress:1;
    unsigned                multipart:1;
    unsigned                resolve_url:1;
    unsigned                get_as_binary:1;
    ngx_uint_t              max_redirects;
    
    /* SSL options */
    ngx_str_t               client_cert;
    ngx_str_t               client_cert_password;
    ngx_str_t               ca_cert;
    unsigned                verify_ssl:1;
    
    /* Proxy */
    ngx_str_t               proxy_server;
    ngx_uint_t              proxy_port;
    ngx_str_t               proxy_user;
    ngx_str_t               proxy_password;
    
    /* User agent */
    ngx_str_t               user_agent;
    
    /* Charset */
    ngx_str_t               charset;
    
    /* Result variable name (for cfhttp tag) */
    ngx_str_t               result;
    
    /* Pool for allocations */
    ngx_pool_t              *pool;
} cfml_http_request_t;

/* HTTP response */
typedef struct {
    ngx_int_t               status_code;
    ngx_str_t               status_text;
    ngx_str_t               http_version;
    
    /* Response headers */
    ngx_array_t             *headers;       /* Array of cfml_http_header_t */
    cfml_struct_t           *header_struct; /* Headers as struct for easy access */
    
    /* Response body */
    ngx_str_t               content;
    ngx_str_t               content_type;
    size_t                  content_length;
    ngx_str_t               charset;
    
    /* Binary response */
    u_char                  *file_content;
    size_t                  file_size;
    
    /* Metadata */
    ngx_str_t               final_url;      /* After redirects */
    ngx_str_t               response_header;/* Raw response header */
    ngx_msec_t              response_time;
    
    /* Error info */
    unsigned                succeeded:1;
    unsigned                timed_out:1;
    unsigned                connection_failed:1;
    unsigned                ssl_error:1;
    ngx_str_t               error_detail;
    
    /* Cookies received */
    ngx_array_t             *cookies;       /* Array of cookie structs */
    
    ngx_pool_t              *pool;
} cfml_http_response_t;

/* Connection pool entry */
typedef struct {
    ngx_str_t               host;
    ngx_uint_t              port;
    unsigned                ssl:1;
    ngx_socket_t            socket;
    ngx_msec_t              last_used;
    unsigned                in_use:1;
    ngx_queue_t             queue;
} cfml_http_conn_t;

/* Connection pool */
typedef struct {
    ngx_pool_t              *pool;
    ngx_queue_t             free_connections;
    ngx_queue_t             active_connections;
    ngx_uint_t              max_connections;
    ngx_uint_t              connection_count;
    ngx_msec_t              keepalive_timeout;
} cfml_http_pool_t;

/*
 * HTTP Client API
 */

/* Initialize HTTP module */
ngx_int_t cfml_http_init(ngx_cycle_t *cycle);

/* Cleanup HTTP module */
void cfml_http_cleanup(ngx_cycle_t *cycle);

/* Create new request */
cfml_http_request_t *cfml_http_request_create(ngx_pool_t *pool);

/* Add header to request */
ngx_int_t cfml_http_add_header(cfml_http_request_t *req, ngx_str_t *name, ngx_str_t *value);

/* Add parameter to request */
ngx_int_t cfml_http_add_param(cfml_http_request_t *req, ngx_str_t *name, 
                               ngx_str_t *value, cfml_content_type_t type);

/* Add form field */
ngx_int_t cfml_http_add_form_field(cfml_http_request_t *req, ngx_str_t *name,
                                    ngx_str_t *value);

/* Add file upload */
ngx_int_t cfml_http_add_file(cfml_http_request_t *req, ngx_str_t *name,
                              ngx_str_t *filepath, ngx_str_t *content_type);

/* Execute HTTP request (synchronous) */
cfml_http_response_t *cfml_http_execute(cfml_http_request_t *req);

/* Execute HTTP request (asynchronous - returns immediately) */
ngx_int_t cfml_http_execute_async(cfml_http_request_t *req,
                                   void (*callback)(cfml_http_response_t *resp, void *data),
                                   void *callback_data);

/* Quick request methods */
cfml_http_response_t *cfml_http_get(ngx_pool_t *pool, ngx_str_t *url);
cfml_http_response_t *cfml_http_post(ngx_pool_t *pool, ngx_str_t *url, 
                                      ngx_str_t *body, ngx_str_t *content_type);
cfml_http_response_t *cfml_http_post_json(ngx_pool_t *pool, ngx_str_t *url, 
                                           cfml_value_t *json_data);

/* Convert response to CFML struct (cfhttp.xxx format) */
cfml_struct_t *cfml_http_response_to_struct(ngx_pool_t *pool, 
                                             cfml_http_response_t *resp);

/* Parse URL into components */
typedef struct {
    ngx_str_t               scheme;
    ngx_str_t               host;
    ngx_uint_t              port;
    ngx_str_t               path;
    ngx_str_t               query;
    ngx_str_t               fragment;
    ngx_str_t               userinfo;
} cfml_parsed_url_t;

ngx_int_t cfml_parse_url(ngx_pool_t *pool, ngx_str_t *url, cfml_parsed_url_t *parsed);

/* URL encoding/decoding */
ngx_str_t *cfml_url_encode(ngx_pool_t *pool, ngx_str_t *input);
ngx_str_t *cfml_url_decode(ngx_pool_t *pool, ngx_str_t *input);

/* Build query string from struct */
ngx_str_t *cfml_build_query_string(ngx_pool_t *pool, cfml_struct_t *params);

/* Parse query string to struct */
cfml_struct_t *cfml_parse_query_string(ngx_pool_t *pool, ngx_str_t *query);

/*
 * CFML Tag and Function implementations
 */

/* cfhttp tag handler */
ngx_int_t cfml_tag_http(cfml_context_t *ctx, cfml_ast_node_t *node);

/* cfhttpparam tag handler */
ngx_int_t cfml_tag_httpparam(cfml_context_t *ctx, cfml_ast_node_t *node);

/* CFML function: HTTPRequest() - modern alternative to cfhttp */
cfml_value_t *cfml_func_httprequest(cfml_context_t *ctx, ngx_array_t *args);

/* CFML function: HTTPResponse() - parse raw response */
cfml_value_t *cfml_func_httpresponse(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_HTTP_H_ */
