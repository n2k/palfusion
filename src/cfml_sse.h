/*
 * CFML SSE - Server-Sent Events support
 * Real-time server-to-client event streaming
 */

#ifndef _CFML_SSE_H_
#define _CFML_SSE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cfml_types.h"

/* SSE event structure */
typedef struct {
    ngx_str_t           id;         /* Event ID */
    ngx_str_t           event;      /* Event type (default: "message") */
    ngx_str_t           data;       /* Event data */
    ngx_int_t           retry;      /* Reconnection time in ms (-1 = don't send) */
} cfml_sse_event_t;

/* SSE connection context */
typedef struct {
    ngx_http_request_t  *r;
    ngx_pool_t          *pool;
    ngx_chain_t         *out;
    ngx_chain_t         **last;
    unsigned            headers_sent:1;
    unsigned            closed:1;
    ngx_uint_t          event_count;
    ngx_str_t           last_event_id;
} cfml_sse_ctx_t;

/*
 * SSE Functions
 */

/* Initialize SSE response (sets headers) */
cfml_sse_ctx_t *cfml_sse_init(ngx_http_request_t *r);

/* Send SSE event */
ngx_int_t cfml_sse_send(cfml_sse_ctx_t *ctx, cfml_sse_event_t *event);

/* Send simple message (event type = "message") */
ngx_int_t cfml_sse_send_message(cfml_sse_ctx_t *ctx, ngx_str_t *data);

/* Send named event */
ngx_int_t cfml_sse_send_event(cfml_sse_ctx_t *ctx, ngx_str_t *event_type,
    ngx_str_t *data, ngx_str_t *id);

/* Send JSON data as event */
ngx_int_t cfml_sse_send_json(cfml_sse_ctx_t *ctx, cfml_value_t *data,
    ngx_str_t *event_type);

/* Send retry directive */
ngx_int_t cfml_sse_set_retry(cfml_sse_ctx_t *ctx, ngx_int_t milliseconds);

/* Send comment (keep-alive) */
ngx_int_t cfml_sse_send_comment(cfml_sse_ctx_t *ctx, ngx_str_t *comment);

/* Flush buffered events */
ngx_int_t cfml_sse_flush(cfml_sse_ctx_t *ctx);

/* Close SSE stream */
ngx_int_t cfml_sse_close(cfml_sse_ctx_t *ctx);

/* Get Last-Event-ID from request header */
ngx_str_t *cfml_sse_get_last_event_id(ngx_http_request_t *r);

/*
 * CFML Tag/Function Implementations
 */

/* cfflush tag - flush output buffer (enables streaming) */
ngx_int_t cfml_tag_flush(cfml_context_t *ctx, cfml_ast_node_t *node);

/* SSEInit() - Initialize SSE stream */
cfml_value_t *cfml_func_sseinit(cfml_context_t *ctx, ngx_array_t *args);

/* SSESend(data [, eventType] [, id]) - Send event */
cfml_value_t *cfml_func_ssesend(cfml_context_t *ctx, ngx_array_t *args);

/* SSEClose() - Close stream */
cfml_value_t *cfml_func_sseclose(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_SSE_H_ */
