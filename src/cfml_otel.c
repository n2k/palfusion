/*
 * CFML OpenTelemetry - Distributed tracing implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cfml_otel.h"
#include "cfml_http.h"
#include "cfml_variables.h"

static cfml_otel_config_t *otel_config = NULL;
static cfml_otel_span_t *current_span = NULL;

/* Generate random hex bytes */
static void
generate_random_hex(u_char *buf, size_t len)
{
    size_t i;
    static const char hex[] = "0123456789abcdef";
    
    for (i = 0; i < len; i++) {
        buf[i] = hex[ngx_random() & 0xf];
    }
}

ngx_int_t
cfml_otel_init(ngx_pool_t *pool, cfml_otel_config_t *config)
{
    otel_config = ngx_pcalloc(pool, sizeof(cfml_otel_config_t));
    if (otel_config == NULL) {
        return NGX_ERROR;
    }
    
    *otel_config = *config;
    otel_config->enabled = 1;
    return NGX_OK;
}

/* Extract W3C Trace Context from headers */
cfml_otel_context_t *
cfml_otel_extract(ngx_http_request_t *r, ngx_pool_t *pool)
{
    cfml_otel_context_t *ctx;
    ngx_table_elt_t *h;
    ngx_list_part_t *part;
    ngx_uint_t i;
    
    ctx = ngx_pcalloc(pool, sizeof(cfml_otel_context_t));
    if (ctx == NULL) {
        return NULL;
    }
    
    /* Look for traceparent header */
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
        
        if (h[i].key.len == 11 &&
            ngx_strncasecmp(h[i].key.data, (u_char *)"traceparent", 11) == 0) {
            /* Parse: version-traceid-spanid-flags */
            /* Format: 00-{32 hex}-{16 hex}-{2 hex} */
            if (h[i].value.len >= 55) {
                ngx_memcpy(ctx->trace_id, h[i].value.data + 3, 32);
                ngx_memcpy(ctx->span_id, h[i].value.data + 36, 16);
                ctx->trace_flags = h[i].value.data[53];
            }
            break;
        }
    }
    
    /* Generate new IDs if not found */
    if (ctx->trace_id[0] == 0) {
        generate_random_hex(ctx->trace_id, 32);
        generate_random_hex(ctx->span_id, 16);
        ctx->trace_flags = '0';
    }
    
    return ctx;
}

ngx_int_t
cfml_otel_inject(cfml_otel_context_t *ctx, cfml_http_request_t *req)
{
    ngx_str_t name, value;
    u_char buf[64];
    
    if (ctx == NULL || req == NULL) {
        return NGX_ERROR;
    }
    
    ngx_str_set(&name, "traceparent");
    
    /* Format: 00-{traceid}-{spanid}-{flags} */
    ngx_snprintf(buf, sizeof(buf), "00-%.32s-%.16s-%c%Z",
                 ctx->trace_id, ctx->span_id, ctx->trace_flags);
    value.data = buf;
    value.len = ngx_strlen(buf);
    
    return cfml_http_add_header(req, &name, &value);
}

cfml_otel_span_t *
cfml_otel_span_start(ngx_pool_t *pool, ngx_str_t *name,
    cfml_otel_context_t *parent, cfml_otel_span_kind_t kind)
{
    cfml_otel_span_t *span;
    
    span = ngx_pcalloc(pool, sizeof(cfml_otel_span_t));
    if (span == NULL) {
        return NULL;
    }
    
    span->pool = pool;
    span->name = *name;
    span->kind = kind;
    span->start_time = ngx_current_msec;
    span->attributes = cfml_struct_new(pool);
    
    if (parent) {
        span->parent = *parent;
        ngx_memcpy(span->context.trace_id, parent->trace_id, 32);
    } else {
        generate_random_hex(span->context.trace_id, 32);
    }
    
    generate_random_hex(span->context.span_id, 16);
    span->context.trace_flags = '1';
    
    current_span = span;
    return span;
}

ngx_int_t
cfml_otel_span_set_attr(cfml_otel_span_t *span, ngx_str_t *key, cfml_value_t *value)
{
    if (span == NULL || span->attributes == NULL) {
        return NGX_ERROR;
    }
    
    return cfml_struct_set(span->attributes, key, value) == NGX_OK ? NGX_OK : NGX_ERROR;
}

ngx_int_t
cfml_otel_span_add_event(cfml_otel_span_t *span, ngx_str_t *name,
    cfml_struct_t *attributes)
{
    (void)span;
    (void)name;
    (void)attributes;
    /* TODO: Implement event recording */
    return NGX_OK;
}

ngx_int_t
cfml_otel_span_set_status(cfml_otel_span_t *span, cfml_otel_status_t status,
    ngx_str_t *message)
{
    if (span == NULL) {
        return NGX_ERROR;
    }
    
    span->status = status;
    if (message) {
        span->status_message = *message;
    }
    return NGX_OK;
}

ngx_int_t
cfml_otel_span_end(cfml_otel_span_t *span)
{
    if (span == NULL) {
        return NGX_ERROR;
    }
    
    span->end_time = ngx_current_msec;
    
    /* TODO: Export span to OTLP endpoint */
    
    if (current_span == span) {
        current_span = NULL;
    }
    
    return NGX_OK;
}

/* CFML Function implementations */
cfml_value_t *
cfml_func_tracestart(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_otel_span_t *span;
    ngx_str_t name;
    cfml_otel_context_t *parent;
    
    ngx_str_set(&name, "request");
    
    if (args != NULL && args->nelts >= 1) {
        argv = args->elts;
        if (argv[0]->type == CFML_TYPE_STRING) {
            name = argv[0]->data.string;
        }
    }
    
    parent = cfml_otel_extract(ctx->r, ctx->pool);
    span = cfml_otel_span_start(ctx->pool, &name, parent, OTEL_SPAN_SERVER);
    
    if (span == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Return trace context as struct */
    cfml_value_t *result = cfml_create_struct(ctx->pool);
    ngx_str_t key;
    
    ngx_str_set(&key, "traceId");
    cfml_struct_set(result->data.structure, &key,
        cfml_create_string_cstr(ctx->pool, (char *)span->context.trace_id));
    
    ngx_str_set(&key, "spanId");
    cfml_struct_set(result->data.structure, &key,
        cfml_create_string_cstr(ctx->pool, (char *)span->context.span_id));
    
    return result;
}

cfml_value_t *
cfml_func_traceend(cfml_context_t *ctx, ngx_array_t *args)
{
    (void)args;
    
    if (current_span == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    cfml_otel_span_end(current_span);
    return cfml_create_boolean(ctx->pool, 1);
}

cfml_value_t *
cfml_func_traceset(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    
    if (current_span == NULL || args == NULL || args->nelts < 2) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    cfml_otel_span_set_attr(current_span, &argv[0]->data.string, argv[1]);
    return cfml_create_boolean(ctx->pool, 1);
}

cfml_value_t *
cfml_func_traceevent(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    
    if (current_span == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    cfml_otel_span_add_event(current_span, &argv[0]->data.string, NULL);
    return cfml_create_boolean(ctx->pool, 1);
}
