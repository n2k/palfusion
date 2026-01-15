/*
 * ngx_http_cfml_module - CFML support for nginx
 * Copyright (c) 2026
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "src/cfml_types.h"
#include "src/cfml_parser.h"
#include "src/cfml_lexer.h"
#include "src/cfml_runtime.h"
#include "src/cfml_functions.h"
#include "src/cfml_variables.h"
#include "src/cfml_cache.h"
#include "src/cfml_session.h"
#include "src/cfml_fastcgi.h"
#include "src/cfml_component.h"

/* Module declarations */
static ngx_int_t ngx_http_cfml_handler(ngx_http_request_t *r);
static void *ngx_http_cfml_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_cfml_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_cfml_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cfml_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_cfml_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cfml_init_process(ngx_cycle_t *cycle);
static void ngx_http_cfml_exit_process(ngx_cycle_t *cycle);
static char *ngx_http_cfml_set_datasource(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Configuration directives */
static ngx_command_t ngx_http_cfml_commands[] = {

    { ngx_string("cfml"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, enable),
      NULL },

    { ngx_string("cfml_root"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, root),
      NULL },

    { ngx_string("cfml_index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, index),
      NULL },

    { ngx_string("cfml_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, cache),
      NULL },

    { ngx_string("cfml_cache_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, cache_size),
      NULL },

    { ngx_string("cfml_fastcgi_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, fastcgi_pass),
      NULL },

    { ngx_string("cfml_error_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, error_page),
      NULL },

    { ngx_string("cfml_strict_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, strict_mode),
      NULL },

    { ngx_string("cfml_application_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, application_timeout),
      NULL },

    { ngx_string("cfml_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, session_timeout),
      NULL },

    { ngx_string("cfml_request_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, request_timeout),
      NULL },

    { ngx_string("cfml_max_include_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cfml_loc_conf_t, max_include_depth),
      NULL },

    { ngx_string("cfml_datasource"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_http_cfml_set_datasource,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_cfml_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_cfml_init,                     /* postconfiguration */

    ngx_http_cfml_create_main_conf,         /* create main configuration */
    ngx_http_cfml_init_main_conf,           /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_cfml_create_loc_conf,          /* create location configuration */
    ngx_http_cfml_merge_loc_conf            /* merge location configuration */
};

/* Module definition */
ngx_module_t ngx_http_cfml_module = {
    NGX_MODULE_V1,
    &ngx_http_cfml_module_ctx,              /* module context */
    ngx_http_cfml_commands,                 /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_http_cfml_init_process,             /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_cfml_exit_process,             /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Create main configuration */
static void *
ngx_http_cfml_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_cfml_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cfml_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->datasources = ngx_array_create(cf->pool, 4, sizeof(cfml_datasource_t));
    if (conf->datasources == NULL) {
        return NULL;
    }

    return conf;
}

/* Initialize main configuration */
static char *
ngx_http_cfml_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_cfml_main_conf_t *mcf = conf;

    /* Initialize built-in functions hash */
    if (cfml_init_builtin_functions(cf, &mcf->builtin_functions) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Create location configuration */
static void *
ngx_http_cfml_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cfml_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cfml_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->cache = NGX_CONF_UNSET;
    conf->cache_size = NGX_CONF_UNSET_SIZE;
    conf->strict_mode = NGX_CONF_UNSET;
    conf->application_timeout = NGX_CONF_UNSET_MSEC;
    conf->session_timeout = NGX_CONF_UNSET_MSEC;
    conf->request_timeout = NGX_CONF_UNSET_MSEC;
    conf->max_include_depth = NGX_CONF_UNSET_UINT;

    return conf;
}

/* Merge location configuration */
static char *
ngx_http_cfml_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cfml_loc_conf_t *prev = parent;
    ngx_http_cfml_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->root, prev->root, "");
    ngx_conf_merge_value(conf->cache, prev->cache, 0);
    ngx_conf_merge_size_value(conf->cache_size, prev->cache_size, 10 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->fastcgi_pass, prev->fastcgi_pass, "");
    ngx_conf_merge_str_value(conf->error_page, prev->error_page, "");
    ngx_conf_merge_value(conf->strict_mode, prev->strict_mode, 0);
    ngx_conf_merge_msec_value(conf->application_timeout, prev->application_timeout, 
                              24 * 60 * 60 * 1000);
    ngx_conf_merge_msec_value(conf->session_timeout, prev->session_timeout, 
                              20 * 60 * 1000);
    ngx_conf_merge_msec_value(conf->request_timeout, prev->request_timeout,
                              30 * 1000);
    ngx_conf_merge_uint_value(conf->max_include_depth, prev->max_include_depth, 100);

    /* Merge index files */
    if (conf->index == NULL) {
        conf->index = prev->index;
    }

    /* Default index if not set */
    if (conf->index == NULL) {
        conf->index = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
        if (conf->index == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_str_t *idx = ngx_array_push(conf->index);
        if (idx == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_str_set(idx, "index.cfm");
    }

    return NGX_CONF_OK;
}

/* Parse datasource configuration */
static char *
ngx_http_cfml_set_datasource(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cfml_main_conf_t *mcf;
    ngx_str_t *value;
    cfml_datasource_t *ds;

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_cfml_module);

    value = cf->args->elts;

    ds = ngx_array_push(mcf->datasources);
    if (ds == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ds, sizeof(cfml_datasource_t));

    ds->name = value[1];
    ds->connection_string = value[2];

    /* Parse connection string for individual components */
    /* Format: driver://user:pass@host:port/database */
    if (cfml_parse_connection_string(cf->pool, &ds->connection_string, ds) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid datasource connection string: \"%V\"",
                           &ds->connection_string);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Module initialization */
static ngx_int_t
ngx_http_cfml_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cfml_handler;

    return NGX_OK;
}

/* Process initialization */
static ngx_int_t
ngx_http_cfml_init_process(ngx_cycle_t *cycle)
{
    /* Initialize template cache */
    if (cfml_cache_init(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Initialize session storage */
    if (cfml_session_init(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Process exit */
static void
ngx_http_cfml_exit_process(ngx_cycle_t *cycle)
{
    cfml_cache_cleanup(cycle);
    cfml_session_cleanup(cycle);
}

/* Resolve file path */
static ngx_int_t
ngx_http_cfml_resolve_path(ngx_http_request_t *r, ngx_http_cfml_loc_conf_t *lcf,
                           ngx_str_t *path)
{
    u_char *last;
    size_t root_len;
    ngx_str_t root;

    /* Get the root directory */
    if (lcf->root.len > 0) {
        root = lcf->root;
    } else {        
        if (ngx_http_map_uri_to_path(r, &root, &root_len, 0) == NULL) {
            return NGX_ERROR;
        }
        root.len = root_len;
    }

    /* Allocate memory for the full path */
    path->len = root.len + r->uri.len;
    path->data = ngx_pnalloc(r->pool, path->len + 1);
    if (path->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_copy(path->data, root.data, root.len);
    last = ngx_copy(last, r->uri.data, r->uri.len);
    *last = '\0';

    return NGX_OK;
}

/* Check if file exists and is CFML */
static ngx_int_t
ngx_http_cfml_check_file(ngx_http_request_t *r, ngx_str_t *path)
{
    ngx_file_info_t fi;
    u_char *ext, *p;

    if (ngx_file_info(path->data, &fi) == NGX_FILE_ERROR) {
        return NGX_DECLINED;
    }

    if (!ngx_is_file(&fi)) {
        return NGX_DECLINED;
    }

    /* Check extension - find last dot */
    ext = NULL;
    for (p = path->data + path->len - 1; p >= path->data; p--) {
        if (*p == '.') {
            ext = p;
            break;
        }
    }
    if (ext == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_strcasecmp(ext, (u_char *)".cfm") == 0 ||
        ngx_strcasecmp(ext, (u_char *)".cfc") == 0 ||
        ngx_strcasecmp(ext, (u_char *)".cfml") == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/* Create execution context */
static cfml_context_t *
ngx_http_cfml_create_context(ngx_http_request_t *r, ngx_http_cfml_loc_conf_t *lcf)
{
    cfml_context_t *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(cfml_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->r = r;
    ctx->pool = r->pool;
    ctx->max_include_depth = lcf->max_include_depth;

    /* Initialize output chain */
    ctx->output_last = &ctx->output_chain;

    /* Initialize variable scopes */
    if (cfml_init_scopes(ctx) != NGX_OK) {
        return NULL;
    }

    /* Parse URL parameters into url scope */
    if (cfml_parse_url_params(ctx) != NGX_OK) {
        return NULL;
    }

    /* Parse form data if POST */
    if (r->method == NGX_HTTP_POST) {
        if (cfml_parse_form_data(ctx) != NGX_OK) {
            return NULL;
        }
    }

    /* Populate CGI scope */
    if (cfml_populate_cgi_scope(ctx) != NGX_OK) {
        return NULL;
    }

    /* Parse cookies */
    if (cfml_parse_cookies(ctx) != NGX_OK) {
        return NULL;
    }

    /* Initialize session scope */
    if (cfml_init_session(ctx, lcf->session_timeout) != NGX_OK) {
        return NULL;
    }

    /* Initialize savecontent stack */
    ctx->savecontent_stack = ngx_array_create(r->pool, 4, sizeof(ngx_buf_t *));
    if (ctx->savecontent_stack == NULL) {
        return NULL;
    }

    return ctx;
}

/* Send CFML response */
static ngx_int_t
ngx_http_cfml_send_response(ngx_http_request_t *r, cfml_context_t *ctx)
{
    ngx_int_t rc;

    /* Check for redirect */
    if (r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY ||
        r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY)
    {
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    /* Set default content type if not set */
    if (r->headers_out.content_type.len == 0) {
        ngx_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_len = r->headers_out.content_type.len;
    }

    /* Set content length */
    r->headers_out.content_length_n = ctx->output_size;

    if (r->headers_out.status == 0) {
        r->headers_out.status = NGX_HTTP_OK;
    }

    /* Send headers */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* Send body */
    if (ctx->output_chain == NULL) {
        /* Empty response */
        ngx_buf_t *b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        b->last_buf = 1;
        b->last_in_chain = 1;
        
        ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
        if (out == NULL) {
            return NGX_ERROR;
        }
        out->buf = b;
        out->next = NULL;
        
        return ngx_http_output_filter(r, out);
    }

    /* Mark last buffer */
    ngx_chain_t *cl;
    for (cl = ctx->output_chain; cl->next; cl = cl->next) {
        /* Traverse to last */
    }
    cl->buf->last_buf = 1;
    cl->buf->last_in_chain = 1;

    return ngx_http_output_filter(r, ctx->output_chain);
}

/* Handle CFML error */
static ngx_int_t
ngx_http_cfml_handle_error(ngx_http_request_t *r, cfml_context_t *ctx,
                           ngx_http_cfml_loc_conf_t *lcf)
{
    ngx_chain_t *out;
    ngx_buf_t *b;
    size_t len;
    u_char *p;

    /* If custom error page is configured, use it */
    if (lcf->error_page.len > 0) {
        /* TODO: Include error page template */
    }

    /* Generate default error page */
    len = sizeof("<html><head><title>CFML Error</title></head><body>") - 1
        + sizeof("<h1>CFML Error</h1><pre>") - 1
        + ctx->error_message.len
        + sizeof("</pre><p>Line: </p></body></html>") - 1
        + NGX_INT_T_LEN;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_sprintf(b->pos,
        "<html><head><title>CFML Error</title></head><body>"
        "<h1>CFML Error</h1><pre>%V</pre>"
        "<p>Line: %ui</p></body></html>",
        &ctx->error_message, ctx->error_line);

    b->last = p;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out->buf = b;
    out->next = NULL;

    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.content_length_n = p - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/html");

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, out);
}

/* Forward declaration */
static void ngx_http_cfml_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cfml_process_request(ngx_http_request_t *r);

/* POST body handler */
static void
ngx_http_cfml_post_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    
    rc = ngx_http_cfml_process_request(r);
    
    ngx_http_finalize_request(r, rc);
}

/* Main request handler */
static ngx_int_t
ngx_http_cfml_handler(ngx_http_request_t *r)
{
    ngx_http_cfml_loc_conf_t *lcf;
    ngx_str_t path;
    ngx_int_t rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_cfml_module);

    /* Check if CFML is enabled */
    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    /* Only handle GET, POST, HEAD */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Resolve file path */
    if (ngx_http_cfml_resolve_path(r, lcf, &path) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check if file exists and is CFML */
    rc = ngx_http_cfml_check_file(r, &path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Read request body for POST */
    if (r->method == NGX_HTTP_POST) {
        rc = ngx_http_read_client_request_body(r, ngx_http_cfml_post_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }
    
    return ngx_http_cfml_process_request(r);
}

/* Process the CFML request */
static ngx_int_t
ngx_http_cfml_process_request(ngx_http_request_t *r)
{
    ngx_http_cfml_loc_conf_t *lcf;
    cfml_context_t *ctx;
    cfml_template_t *tmpl;
    ngx_str_t path;
    ngx_int_t rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_cfml_module);
    
    /* Resolve file path */
    if (ngx_http_cfml_resolve_path(r, lcf, &path) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create execution context */
    ctx = ngx_http_cfml_create_context(r, lcf);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check for Application.cfc */
    rc = cfml_load_application_cfc(ctx, &path);
    if (rc != NGX_OK && rc != NGX_DECLINED) {
        return ngx_http_cfml_handle_error(r, ctx, lcf);
    }

    /* Call onRequestStart if Application.cfc exists */
    if (ctx->application_cfc != NULL) {
        rc = cfml_invoke_application_method(ctx, "onRequestStart", &path);
        if (rc != NGX_OK) {
            return ngx_http_cfml_handle_error(r, ctx, lcf);
        }
    }

    /* Parse template (or get from cache) */
    tmpl = cfml_parse_template(r->pool, &path, lcf->cache);
    if (tmpl == NULL) {
        ngx_str_set(&ctx->error_message, "Failed to parse template");
        return ngx_http_cfml_handle_error(r, ctx, lcf);
    }

    ctx->current_template = tmpl;

    /* Execute template */
    rc = cfml_execute(ctx, tmpl->root);
    if (rc != NGX_OK) {
        /* Check for onError handler */
        if (ctx->application_cfc != NULL) {
            rc = cfml_invoke_application_method(ctx, "onError", NULL);
            if (rc == NGX_OK) {
                return ngx_http_cfml_send_response(r, ctx);
            }
        }
        return ngx_http_cfml_handle_error(r, ctx, lcf);
    }

    /* Call onRequestEnd if Application.cfc exists */
    if (ctx->application_cfc != NULL) {
        cfml_invoke_application_method(ctx, "onRequestEnd", &path);
    }

    /* Send response */
    return ngx_http_cfml_send_response(r, ctx);
}
