/*
 * CFML OpenTelemetry - Distributed tracing and metrics
 */

#ifndef _CFML_OTEL_H_
#define _CFML_OTEL_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"
#include "cfml_http.h"

/* Span status */
typedef enum {
    OTEL_STATUS_UNSET = 0,
    OTEL_STATUS_OK,
    OTEL_STATUS_ERROR
} cfml_otel_status_t;

/* Span kind */
typedef enum {
    OTEL_SPAN_INTERNAL = 0,
    OTEL_SPAN_SERVER,
    OTEL_SPAN_CLIENT,
    OTEL_SPAN_PRODUCER,
    OTEL_SPAN_CONSUMER
} cfml_otel_span_kind_t;

/* Trace context */
typedef struct {
    u_char              trace_id[32];   /* 16 bytes hex encoded */
    u_char              span_id[16];    /* 8 bytes hex encoded */
    u_char              trace_flags;
} cfml_otel_context_t;

/* Span */
typedef struct {
    ngx_str_t               name;
    cfml_otel_context_t     context;
    cfml_otel_context_t     parent;
    cfml_otel_span_kind_t   kind;
    cfml_otel_status_t      status;
    ngx_str_t               status_message;
    ngx_msec_t              start_time;
    ngx_msec_t              end_time;
    cfml_struct_t           *attributes;
    ngx_array_t             *events;
    ngx_pool_t              *pool;
} cfml_otel_span_t;

/* Configuration */
typedef struct {
    ngx_str_t               service_name;
    ngx_str_t               endpoint;       /* OTLP endpoint */
    ngx_str_t               headers;        /* Additional headers */
    unsigned                enabled:1;
} cfml_otel_config_t;

/* Initialize OpenTelemetry */
ngx_int_t cfml_otel_init(ngx_pool_t *pool, cfml_otel_config_t *config);

/* Extract context from request headers */
cfml_otel_context_t *cfml_otel_extract(ngx_http_request_t *r, ngx_pool_t *pool);

/* Inject context into outgoing request */
ngx_int_t cfml_otel_inject(cfml_otel_context_t *ctx, cfml_http_request_t *req);

/* Start span */
cfml_otel_span_t *cfml_otel_span_start(ngx_pool_t *pool, ngx_str_t *name,
    cfml_otel_context_t *parent, cfml_otel_span_kind_t kind);

/* Set span attribute */
ngx_int_t cfml_otel_span_set_attr(cfml_otel_span_t *span, ngx_str_t *key,
    cfml_value_t *value);

/* Add span event */
ngx_int_t cfml_otel_span_add_event(cfml_otel_span_t *span, ngx_str_t *name,
    cfml_struct_t *attributes);

/* Set span status */
ngx_int_t cfml_otel_span_set_status(cfml_otel_span_t *span,
    cfml_otel_status_t status, ngx_str_t *message);

/* End span */
ngx_int_t cfml_otel_span_end(cfml_otel_span_t *span);

/* CFML functions */
cfml_value_t *cfml_func_tracestart(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_traceend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_traceset(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_traceevent(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_OTEL_H_ */
