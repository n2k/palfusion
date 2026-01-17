/*
 * CFML SSE - Server-Sent Events implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cfml_sse.h"
#include "cfml_json.h"
#include "cfml_variables.h"

/* SSE content type */
static ngx_str_t sse_content_type = ngx_string("text/event-stream");
static ngx_str_t sse_cache_control = ngx_string("no-cache");
static ngx_str_t sse_connection = ngx_string("keep-alive");

/* Request context key for SSE */
static cfml_sse_ctx_t *current_sse_ctx = NULL;

/* Initialize SSE response */
cfml_sse_ctx_t *
cfml_sse_init(ngx_http_request_t *r)
{
    cfml_sse_ctx_t *ctx;
    ngx_table_elt_t *h;
    
    ctx = ngx_pcalloc(r->pool, sizeof(cfml_sse_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->r = r;
    ctx->pool = r->pool;
    ctx->last = &ctx->out;
    
    /* Set SSE headers */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = sse_content_type;
    r->headers_out.content_type_len = sse_content_type.len;
    r->headers_out.content_length_n = -1;  /* Unknown length (streaming) */
    
    /* Cache-Control: no-cache */
    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        ngx_str_set(&h->key, "Cache-Control");
        h->value = sse_cache_control;
        h->hash = 1;
    }
    
    /* Connection: keep-alive */
    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        ngx_str_set(&h->key, "Connection");
        h->value = sse_connection;
        h->hash = 1;
    }
    
    /* X-Accel-Buffering: no (for nginx proxies) */
    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        ngx_str_set(&h->key, "X-Accel-Buffering");
        ngx_str_set(&h->value, "no");
        h->hash = 1;
    }
    
    /* Get Last-Event-ID from request */
    ctx->last_event_id.data = NULL;
    ctx->last_event_id.len = 0;
    
    ngx_str_t *last_id = cfml_sse_get_last_event_id(r);
    if (last_id) {
        ctx->last_event_id = *last_id;
    }
    
    /* Send headers */
    ngx_http_send_header(r);
    ctx->headers_sent = 1;
    
    /* Store in global for CFML access */
    current_sse_ctx = ctx;
    
    return ctx;
}

/* Format and add SSE data line */
static ngx_int_t
sse_add_line(cfml_sse_ctx_t *ctx, const char *prefix, ngx_str_t *data)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    size_t len;
    u_char *p, *end, *line_start;
    size_t prefix_len = ngx_strlen(prefix);
    
    if (data == NULL || data->len == 0) {
        return NGX_OK;
    }
    
    /* Calculate size: each line needs "prefix: data\n" */
    /* Multi-line data needs to be split */
    len = 0;
    p = data->data;
    end = data->data + data->len;
    
    while (p < end) {
        /* Find end of line */
        line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        
        len += prefix_len + 2 + (p - line_start) + 1;  /* "prefix: line\n" */
        
        /* Skip newline characters */
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;
    }
    
    /* Allocate buffer */
    b = ngx_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }
    
    /* Format data */
    p = data->data;
    while (p < end) {
        line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        
        b->last = ngx_sprintf(b->last, "%s: ", prefix);
        b->last = ngx_copy(b->last, line_start, p - line_start);
        *b->last++ = '\n';
        
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;
    }
    
    /* Add to chain */
    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    
    cl->buf = b;
    cl->next = NULL;
    
    *ctx->last = cl;
    ctx->last = &cl->next;
    
    return NGX_OK;
}

/* Add empty line (event terminator) */
static ngx_int_t
sse_add_newline(cfml_sse_ctx_t *ctx)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    
    b = ngx_create_temp_buf(ctx->pool, 1);
    if (b == NULL) {
        return NGX_ERROR;
    }
    
    *b->last++ = '\n';
    
    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    
    cl->buf = b;
    cl->next = NULL;
    
    *ctx->last = cl;
    ctx->last = &cl->next;
    
    return NGX_OK;
}

/* Send SSE event */
ngx_int_t
cfml_sse_send(cfml_sse_ctx_t *ctx, cfml_sse_event_t *event)
{
    if (ctx == NULL || ctx->closed || event == NULL) {
        return NGX_ERROR;
    }
    
    /* Event ID */
    if (event->id.len > 0) {
        if (sse_add_line(ctx, "id", &event->id) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    /* Event type (if not default "message") */
    if (event->event.len > 0) {
        if (sse_add_line(ctx, "event", &event->event) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    /* Retry */
    if (event->retry >= 0) {
        ngx_str_t retry_str;
        u_char buf[16];
        retry_str.data = buf;
        retry_str.len = ngx_sprintf(buf, "%d", (int)event->retry) - buf;
        if (sse_add_line(ctx, "retry", &retry_str) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    /* Data */
    if (event->data.len > 0) {
        if (sse_add_line(ctx, "data", &event->data) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    /* Empty line to dispatch event */
    if (sse_add_newline(ctx) != NGX_OK) {
        return NGX_ERROR;
    }
    
    ctx->event_count++;
    
    return NGX_OK;
}

/* Send simple message */
ngx_int_t
cfml_sse_send_message(cfml_sse_ctx_t *ctx, ngx_str_t *data)
{
    cfml_sse_event_t event;
    
    ngx_memzero(&event, sizeof(event));
    event.data = *data;
    event.retry = -1;  /* Don't send retry */
    
    return cfml_sse_send(ctx, &event);
}

/* Send named event */
ngx_int_t
cfml_sse_send_event(cfml_sse_ctx_t *ctx, ngx_str_t *event_type,
    ngx_str_t *data, ngx_str_t *id)
{
    cfml_sse_event_t event;
    
    ngx_memzero(&event, sizeof(event));
    
    if (event_type) {
        event.event = *event_type;
    }
    if (data) {
        event.data = *data;
    }
    if (id) {
        event.id = *id;
    }
    event.retry = -1;
    
    return cfml_sse_send(ctx, &event);
}

/* Send JSON as event */
ngx_int_t
cfml_sse_send_json(cfml_sse_ctx_t *ctx, cfml_value_t *data, ngx_str_t *event_type)
{
    ngx_str_t *json;
    cfml_sse_event_t event;
    
    json = cfml_json_serialize(ctx->pool, data);
    if (json == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memzero(&event, sizeof(event));
    event.data = *json;
    event.retry = -1;
    
    if (event_type) {
        event.event = *event_type;
    }
    
    return cfml_sse_send(ctx, &event);
}

/* Set retry interval */
ngx_int_t
cfml_sse_set_retry(cfml_sse_ctx_t *ctx, ngx_int_t milliseconds)
{
    cfml_sse_event_t event;
    
    ngx_memzero(&event, sizeof(event));
    event.retry = milliseconds;
    
    /* Retry only, no data */
    return cfml_sse_send(ctx, &event);
}

/* Send comment (keep-alive) */
ngx_int_t
cfml_sse_send_comment(cfml_sse_ctx_t *ctx, ngx_str_t *comment)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    
    if (ctx == NULL || ctx->closed) {
        return NGX_ERROR;
    }
    
    /* Format: : comment\n */
    b = ngx_create_temp_buf(ctx->pool, 2 + comment->len + 1);
    if (b == NULL) {
        return NGX_ERROR;
    }
    
    *b->last++ = ':';
    if (comment->len > 0) {
        *b->last++ = ' ';
        b->last = ngx_copy(b->last, comment->data, comment->len);
    }
    *b->last++ = '\n';
    
    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    
    cl->buf = b;
    cl->next = NULL;
    
    *ctx->last = cl;
    ctx->last = &cl->next;
    
    return NGX_OK;
}

/* Flush buffered events */
ngx_int_t
cfml_sse_flush(cfml_sse_ctx_t *ctx)
{
    ngx_int_t rc;
    
    if (ctx == NULL || ctx->closed || ctx->out == NULL) {
        return NGX_OK;
    }
    
    /* Mark last buffer for flushing */
    ngx_chain_t *cl;
    for (cl = ctx->out; cl; cl = cl->next) {
        if (cl->next == NULL) {
            cl->buf->flush = 1;
        }
    }
    
    rc = ngx_http_output_filter(ctx->r, ctx->out);
    
    ctx->out = NULL;
    ctx->last = &ctx->out;
    
    return rc;
}

/* Close SSE stream */
ngx_int_t
cfml_sse_close(cfml_sse_ctx_t *ctx)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    
    if (ctx == NULL || ctx->closed) {
        return NGX_OK;
    }
    
    /* Flush any pending data */
    cfml_sse_flush(ctx);
    
    /* Send final buffer */
    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    
    b->last_buf = 1;
    b->last_in_chain = 1;
    
    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    
    cl->buf = b;
    cl->next = NULL;
    
    rc = ngx_http_output_filter(ctx->r, cl);
    
    ctx->closed = 1;
    current_sse_ctx = NULL;
    
    return rc;
}

/* Get Last-Event-ID from request */
ngx_str_t *
cfml_sse_get_last_event_id(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;
    ngx_list_part_t *part;
    ngx_uint_t i;
    
    part = &r->headers_in.headers.part;
    h = part->elts;
    
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        
        if (h[i].key.len == 13 &&
            ngx_strncasecmp(h[i].key.data, (u_char *)"Last-Event-ID", 13) == 0) {
            return &h[i].value;
        }
    }
    
    return NULL;
}

/*
 * CFML Function Implementations
 */

/* SSEInit() */
cfml_value_t *
cfml_func_sseinit(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_sse_ctx_t *sse_ctx;
    
    (void)args;  /* No arguments */
    
    sse_ctx = cfml_sse_init(ctx->r);
    
    if (sse_ctx == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    return cfml_create_boolean(ctx->pool, 1);
}

/* SSESend(data [, eventType] [, id]) */
cfml_value_t *
cfml_func_ssesend(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_sse_event_t event;
    
    if (current_sse_ctx == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    ngx_memzero(&event, sizeof(event));
    event.retry = -1;
    
    /* Data - convert to string or JSON */
    if (argv[0]->type == CFML_TYPE_STRING) {
        event.data = argv[0]->data.string;
    } else {
        ngx_str_t *json = cfml_json_serialize(ctx->pool, argv[0]);
        if (json) {
            event.data = *json;
        }
    }
    
    /* Event type */
    if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRING) {
        event.event = argv[1]->data.string;
    }
    
    /* Event ID */
    if (args->nelts >= 3 && argv[2]->type == CFML_TYPE_STRING) {
        event.id = argv[2]->data.string;
    }
    
    if (cfml_sse_send(current_sse_ctx, &event) != NGX_OK) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Auto-flush */
    cfml_sse_flush(current_sse_ctx);
    
    return cfml_create_boolean(ctx->pool, 1);
}

/* SSEClose() */
cfml_value_t *
cfml_func_sseclose(cfml_context_t *ctx, ngx_array_t *args)
{
    (void)args;
    
    if (current_sse_ctx == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    cfml_sse_close(current_sse_ctx);
    
    return cfml_create_boolean(ctx->pool, 1);
}

/* cfflush tag handler */
ngx_int_t
cfml_tag_flush(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    (void)node;
    
    /* If in SSE mode, flush SSE */
    if (current_sse_ctx != NULL) {
        return cfml_sse_flush(current_sse_ctx);
    }
    
    /* Otherwise flush regular output */
    /* This would need integration with the main output handler */
    return NGX_OK;
}
