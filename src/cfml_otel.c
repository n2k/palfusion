/*
 * CFML OpenTelemetry - Distributed tracing implementation
 * Supports both HTTP and gRPC OTLP exporters
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cfml_otel.h"
#include "cfml_http.h"
#include "cfml_json.h"
#include "cfml_variables.h"

/* OTLP endpoints */
#define OTLP_HTTP_TRACES  "/v1/traces"
#define OTLP_HTTP_METRICS "/v1/metrics"
#define OTLP_HTTP_LOGS    "/v1/logs"

/* Default config */
static cfml_otel_config_t *otel_config = NULL;

/* Active spans per request */
#define MAX_SPAN_DEPTH 32
typedef struct {
    cfml_otel_span_t    *spans[MAX_SPAN_DEPTH];
    ngx_int_t           depth;
} cfml_span_stack_t;

/* Thread-local span stack (simplified - in nginx context per-request) */
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

/* Generate trace ID (32 hex chars = 16 bytes) */
static void
generate_trace_id(u_char *trace_id)
{
    generate_random_hex(trace_id, 32);
}

/* Generate span ID (16 hex chars = 8 bytes) */
static void
generate_span_id(u_char *span_id)
{
    generate_random_hex(span_id, 16);
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
    
    /* Default to HTTP if not specified */
    if (otel_config->protocol == OTEL_PROTO_UNSET) {
        otel_config->protocol = OTEL_PROTO_HTTP;
    }
    
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
    u_char *p;
    
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
                p = h[i].value.data;
                
                /* Skip version (00-) */
                if (p[0] == '0' && p[1] == '0' && p[2] == '-') {
                    ngx_memcpy(ctx->trace_id, p + 3, 32);
                    ngx_memcpy(ctx->span_id, p + 36, 16);
                    
                    /* Parse flags */
                    if (h[i].value.len >= 55) {
                        ctx->trace_flags = (p[53] >= 'a' ? p[53] - 'a' + 10 : p[53] - '0');
                    }
                    
                    ctx->valid = 1;
                }
            }
            break;
        }
        
        /* Also check for tracestate */
        if (h[i].key.len == 10 &&
            ngx_strncasecmp(h[i].key.data, (u_char *)"tracestate", 10) == 0) {
            ctx->trace_state = h[i].value;
        }
    }
    
    /* Generate new IDs if not found */
    if (!ctx->valid) {
        generate_trace_id(ctx->trace_id);
        generate_span_id(ctx->span_id);
        ctx->trace_flags = 1;  /* Sampled */
        ctx->valid = 1;
    }
    
    return ctx;
}

/* Inject trace context into outgoing HTTP request */
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
    ngx_snprintf(buf, sizeof(buf), "00-%.32s-%.16s-%02xd%Z",
                 ctx->trace_id, ctx->span_id, ctx->trace_flags);
    value.data = buf;
    value.len = 55;
    
    cfml_http_add_header(req, &name, &value);
    
    /* Propagate tracestate if present */
    if (ctx->trace_state.len > 0) {
        ngx_str_set(&name, "tracestate");
        cfml_http_add_header(req, &name, &ctx->trace_state);
    }
    
    return NGX_OK;
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
    span->start_time_unix = (uint64_t)ngx_time() * 1000000000ULL +
                            (ngx_current_msec % 1000) * 1000000ULL;
    span->attributes = cfml_struct_new(pool);
    span->events = ngx_array_create(pool, 4, sizeof(cfml_otel_event_t));
    
    if (parent && parent->valid) {
        span->parent = *parent;
        ngx_memcpy(span->context.trace_id, parent->trace_id, 32);
        /* Parent's span_id becomes our parent_span_id */
        ngx_memcpy(span->parent_span_id, parent->span_id, 16);
    } else if (current_span) {
        /* Inherit from current span */
        ngx_memcpy(span->context.trace_id, current_span->context.trace_id, 32);
        ngx_memcpy(span->parent_span_id, current_span->context.span_id, 16);
    } else {
        generate_trace_id(span->context.trace_id);
    }
    
    generate_span_id(span->context.span_id);
    span->context.trace_flags = 1;
    span->context.valid = 1;
    
    /* Set as current span */
    span->prev_span = current_span;
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
    cfml_otel_event_t *event;
    
    if (span == NULL || span->events == NULL) {
        return NGX_ERROR;
    }
    
    event = ngx_array_push(span->events);
    if (event == NULL) {
        return NGX_ERROR;
    }
    
    event->name = *name;
    event->timestamp = (uint64_t)ngx_time() * 1000000000ULL +
                       (ngx_current_msec % 1000) * 1000000ULL;
    event->attributes = attributes;
    
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

/* Build OTLP JSON payload for HTTP export */
static ngx_str_t *
build_otlp_http_payload(ngx_pool_t *pool, cfml_otel_span_t *span)
{
    cfml_value_t *root, *resource_spans, *rs, *scope_spans, *ss, *spans, *s;
    cfml_value_t *resource, *attrs;
    ngx_str_t key;
    u_char trace_id_str[33], span_id_str[17], parent_id_str[17];
    
    /* Build OTLP structure */
    root = cfml_create_struct(pool);
    
    /* resourceSpans array */
    resource_spans = cfml_create_array(pool);
    ngx_str_set(&key, "resourceSpans");
    cfml_struct_set(root->data.structure, &key, resource_spans);
    
    /* Single resourceSpan */
    rs = cfml_create_struct(pool);
    cfml_array_append(resource_spans->data.array, rs);
    
    /* resource */
    resource = cfml_create_struct(pool);
    ngx_str_set(&key, "resource");
    cfml_struct_set(rs->data.structure, &key, resource);
    
    /* resource.attributes */
    attrs = cfml_create_array(pool);
    ngx_str_set(&key, "attributes");
    cfml_struct_set(resource->data.structure, &key, attrs);
    
    /* Add service.name attribute */
    if (otel_config && otel_config->service_name.len > 0) {
        cfml_value_t *attr = cfml_create_struct(pool);
        ngx_str_set(&key, "key");
        cfml_struct_set(attr->data.structure, &key,
            cfml_create_string_cstr(pool, "service.name"));
        
        cfml_value_t *val = cfml_create_struct(pool);
        ngx_str_set(&key, "stringValue");
        cfml_struct_set(val->data.structure, &key,
            cfml_create_string(pool, &otel_config->service_name));
        
        ngx_str_set(&key, "value");
        cfml_struct_set(attr->data.structure, &key, val);
        
        cfml_array_append(attrs->data.array, attr);
    }
    
    /* scopeSpans array */
    scope_spans = cfml_create_array(pool);
    ngx_str_set(&key, "scopeSpans");
    cfml_struct_set(rs->data.structure, &key, scope_spans);
    
    /* Single scopeSpan */
    ss = cfml_create_struct(pool);
    cfml_array_append(scope_spans->data.array, ss);
    
    /* spans array */
    spans = cfml_create_array(pool);
    ngx_str_set(&key, "spans");
    cfml_struct_set(ss->data.structure, &key, spans);
    
    /* The span itself */
    s = cfml_create_struct(pool);
    cfml_array_append(spans->data.array, s);
    
    /* traceId */
    ngx_memcpy(trace_id_str, span->context.trace_id, 32);
    trace_id_str[32] = '\0';
    ngx_str_set(&key, "traceId");
    cfml_struct_set(s->data.structure, &key,
        cfml_create_string_cstr(pool, (char *)trace_id_str));
    
    /* spanId */
    ngx_memcpy(span_id_str, span->context.span_id, 16);
    span_id_str[16] = '\0';
    ngx_str_set(&key, "spanId");
    cfml_struct_set(s->data.structure, &key,
        cfml_create_string_cstr(pool, (char *)span_id_str));
    
    /* parentSpanId (if any) */
    if (span->parent_span_id[0] != 0) {
        ngx_memcpy(parent_id_str, span->parent_span_id, 16);
        parent_id_str[16] = '\0';
        ngx_str_set(&key, "parentSpanId");
        cfml_struct_set(s->data.structure, &key,
            cfml_create_string_cstr(pool, (char *)parent_id_str));
    }
    
    /* name */
    ngx_str_set(&key, "name");
    cfml_struct_set(s->data.structure, &key,
        cfml_create_string(pool, &span->name));
    
    /* kind */
    ngx_str_set(&key, "kind");
    cfml_struct_set(s->data.structure, &key,
        cfml_create_integer(pool, span->kind + 1));  /* OTLP kind is 1-indexed */
    
    /* startTimeUnixNano */
    ngx_str_set(&key, "startTimeUnixNano");
    u_char time_buf[32];
    ngx_snprintf(time_buf, sizeof(time_buf), "%uL%Z", span->start_time_unix);
    cfml_struct_set(s->data.structure, &key,
        cfml_create_string_cstr(pool, (char *)time_buf));
    
    /* endTimeUnixNano */
    ngx_str_set(&key, "endTimeUnixNano");
    ngx_snprintf(time_buf, sizeof(time_buf), "%uL%Z", span->end_time_unix);
    cfml_struct_set(s->data.structure, &key,
        cfml_create_string_cstr(pool, (char *)time_buf));
    
    /* status */
    if (span->status != OTEL_STATUS_UNSET) {
        cfml_value_t *status = cfml_create_struct(pool);
        ngx_str_set(&key, "code");
        cfml_struct_set(status->data.structure, &key,
            cfml_create_integer(pool, span->status));
        
        if (span->status_message.len > 0) {
            ngx_str_set(&key, "message");
            cfml_struct_set(status->data.structure, &key,
                cfml_create_string(pool, &span->status_message));
        }
        
        ngx_str_set(&key, "status");
        cfml_struct_set(s->data.structure, &key, status);
    }
    
    return cfml_json_serialize(pool, root);
}

/* Build gRPC protobuf payload (simplified - hex encoded) */
static ngx_str_t *
build_otlp_grpc_payload(ngx_pool_t *pool, cfml_otel_span_t *span)
{
    /* Full protobuf encoding would require generated code from .proto files
     * For now, use JSON with gRPC-Web which accepts application/json */
    return build_otlp_http_payload(pool, span);
}

/* Export span via HTTP */
static ngx_int_t
export_span_http(ngx_pool_t *pool, cfml_otel_span_t *span)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *payload, url, header_name, header_value;
    
    if (otel_config == NULL || otel_config->endpoint.len == 0) {
        return NGX_ERROR;
    }
    
    payload = build_otlp_http_payload(pool, span);
    if (payload == NULL) {
        return NGX_ERROR;
    }
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NGX_ERROR;
    }
    
    /* Build URL */
    url.data = ngx_pnalloc(pool, otel_config->endpoint.len + 32);
    url.len = ngx_sprintf(url.data, "%V%s%Z",
                          &otel_config->endpoint, OTLP_HTTP_TRACES) - url.data - 1;
    
    req->url = url;
    req->method = CFML_HTTP_POST;
    req->body = *payload;
    
    /* Set headers */
    ngx_str_set(&header_name, "Content-Type");
    ngx_str_set(&header_value, "application/json");
    cfml_http_add_header(req, &header_name, &header_value);
    
    /* Add custom headers if configured */
    if (otel_config->headers.len > 0) {
        /* Parse and add headers - format: "key1=value1,key2=value2" */
        /* Simplified - just add Authorization if present */
        ngx_str_set(&header_name, "Authorization");
        cfml_http_add_header(req, &header_name, &otel_config->headers);
    }
    
    resp = cfml_http_execute(req);
    
    return (resp && resp->status_code >= 200 && resp->status_code < 300) 
           ? NGX_OK : NGX_ERROR;
}

/* Export span via gRPC */
static ngx_int_t
export_span_grpc(ngx_pool_t *pool, cfml_otel_span_t *span)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *payload, url, header_name, header_value;
    
    if (otel_config == NULL || otel_config->endpoint.len == 0) {
        return NGX_ERROR;
    }
    
    /* Use gRPC-Web with JSON fallback */
    payload = build_otlp_grpc_payload(pool, span);
    if (payload == NULL) {
        return NGX_ERROR;
    }
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NGX_ERROR;
    }
    
    /* gRPC endpoint */
    url.data = ngx_pnalloc(pool, otel_config->endpoint.len + 64);
    url.len = ngx_sprintf(url.data, "%V/opentelemetry.proto.collector.trace.v1.TraceService/Export%Z",
                          &otel_config->endpoint) - url.data - 1;
    
    req->url = url;
    req->method = CFML_HTTP_POST;
    req->body = *payload;
    
    /* gRPC-Web headers */
    ngx_str_set(&header_name, "Content-Type");
    ngx_str_set(&header_value, "application/grpc-web+json");
    cfml_http_add_header(req, &header_name, &header_value);
    
    ngx_str_set(&header_name, "Accept");
    ngx_str_set(&header_value, "application/grpc-web+json");
    cfml_http_add_header(req, &header_name, &header_value);
    
    resp = cfml_http_execute(req);
    
    return (resp && resp->status_code >= 200 && resp->status_code < 300)
           ? NGX_OK : NGX_ERROR;
}

ngx_int_t
cfml_otel_span_end(cfml_otel_span_t *span)
{
    ngx_int_t rc = NGX_OK;
    
    if (span == NULL) {
        return NGX_ERROR;
    }
    
    span->end_time = ngx_current_msec;
    span->end_time_unix = (uint64_t)ngx_time() * 1000000000ULL +
                          (ngx_current_msec % 1000) * 1000000ULL;
    
    /* Export span if configured */
    if (otel_config && otel_config->enabled && otel_config->endpoint.len > 0) {
        if (otel_config->protocol == OTEL_PROTO_GRPC) {
            rc = export_span_grpc(span->pool, span);
        } else {
            rc = export_span_http(span->pool, span);
        }
    }
    
    /* Restore previous span */
    if (current_span == span) {
        current_span = span->prev_span;
    }
    
    return rc;
}

/* Get current active span */
cfml_otel_span_t *
cfml_otel_get_current_span(void)
{
    return current_span;
}

/* ============= CFML Function implementations ============= */

cfml_value_t *
cfml_func_tracestart(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_otel_span_t *span;
    ngx_str_t name;
    cfml_otel_context_t *parent;
    cfml_otel_span_kind_t kind = OTEL_SPAN_SERVER;
    
    ngx_str_set(&name, "request");
    
    if (args != NULL && args->nelts >= 1) {
        argv = args->elts;
        if (argv[0]->type == CFML_TYPE_STRING) {
            name = argv[0]->data.string;
        }
        if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRING) {
            /* Parse kind */
            if (ngx_strncmp(argv[1]->data.string.data, "client", 6) == 0) {
                kind = OTEL_SPAN_CLIENT;
            } else if (ngx_strncmp(argv[1]->data.string.data, "producer", 8) == 0) {
                kind = OTEL_SPAN_PRODUCER;
            } else if (ngx_strncmp(argv[1]->data.string.data, "consumer", 8) == 0) {
                kind = OTEL_SPAN_CONSUMER;
            } else if (ngx_strncmp(argv[1]->data.string.data, "internal", 8) == 0) {
                kind = OTEL_SPAN_INTERNAL;
            }
        }
    }
    
    parent = cfml_otel_extract(ctx->r, ctx->pool);
    span = cfml_otel_span_start(ctx->pool, &name, parent, kind);
    
    if (span == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Return trace context as struct */
    cfml_value_t *result = cfml_create_struct(ctx->pool);
    ngx_str_t key;
    u_char buf[33];
    
    ngx_str_set(&key, "traceId");
    ngx_memcpy(buf, span->context.trace_id, 32);
    buf[32] = '\0';
    cfml_struct_set(result->data.structure, &key,
        cfml_create_string_cstr(ctx->pool, (char *)buf));
    
    ngx_str_set(&key, "spanId");
    ngx_memcpy(buf, span->context.span_id, 16);
    buf[16] = '\0';
    cfml_struct_set(result->data.structure, &key,
        cfml_create_string_cstr(ctx->pool, (char *)buf));
    
    ngx_str_set(&key, "sampled");
    cfml_struct_set(result->data.structure, &key,
        cfml_create_boolean(ctx->pool, span->context.trace_flags & 1));
    
    return result;
}

cfml_value_t *
cfml_func_traceend(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_otel_status_t status = OTEL_STATUS_OK;
    ngx_str_t *message = NULL;
    
    if (current_span == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Optional status */
    if (args != NULL && args->nelts >= 1) {
        argv = args->elts;
        if (argv[0]->type == CFML_TYPE_STRING) {
            if (ngx_strncmp(argv[0]->data.string.data, "error", 5) == 0) {
                status = OTEL_STATUS_ERROR;
            }
        } else         if (argv[0]->type == CFML_TYPE_INTEGER) {
            status = (cfml_otel_status_t)argv[0]->data.integer;
        }
        
        if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRING) {
            message = &argv[1]->data.string;
        }
    }
    
    cfml_otel_span_set_status(current_span, status, message);
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
    cfml_struct_t *attrs = NULL;
    
    if (current_span == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRUCT) {
        attrs = argv[1]->data.structure;
    }
    
    cfml_otel_span_add_event(current_span, &argv[0]->data.string, attrs);
    return cfml_create_boolean(ctx->pool, 1);
}

/* Configure OTEL at runtime */
cfml_value_t *
cfml_func_traceconfig(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_otel_config_t config;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRUCT) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    ngx_memzero(&config, sizeof(config));
    
    /* Parse config struct */
    ngx_str_t key;
    cfml_value_t *val;
    
    ngx_str_set(&key, "endpoint");
    val = cfml_struct_get(argv[0]->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) config.endpoint = val->data.string;
    
    ngx_str_set(&key, "serviceName");
    val = cfml_struct_get(argv[0]->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) config.service_name = val->data.string;
    
    ngx_str_set(&key, "headers");
    val = cfml_struct_get(argv[0]->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) config.headers = val->data.string;
    
    ngx_str_set(&key, "protocol");
    val = cfml_struct_get(argv[0]->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        if (ngx_strncmp(val->data.string.data, "grpc", 4) == 0) {
            config.protocol = OTEL_PROTO_GRPC;
        } else {
            config.protocol = OTEL_PROTO_HTTP;
        }
    }
    
    cfml_otel_init(ctx->pool, &config);
    
    return cfml_create_boolean(ctx->pool, 1);
}
