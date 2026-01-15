/*
 * CFML Variables - Variable scope management implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cfml_variables.h"
#include "cfml_runtime.h"

/* Initialize all scopes */
ngx_int_t
cfml_init_scopes(cfml_context_t *ctx)
{
    ctx->variables_scope = cfml_struct_new(ctx->pool);
    ctx->local_scope = cfml_struct_new(ctx->pool);
    ctx->arguments_scope = cfml_struct_new(ctx->pool);
    ctx->url_scope = cfml_struct_new(ctx->pool);
    ctx->form_scope = cfml_struct_new(ctx->pool);
    ctx->cgi_scope = cfml_struct_new(ctx->pool);
    ctx->cookie_scope = cfml_struct_new(ctx->pool);
    ctx->request_scope = cfml_struct_new(ctx->pool);

    if (ctx->variables_scope == NULL || ctx->local_scope == NULL ||
        ctx->arguments_scope == NULL || ctx->url_scope == NULL ||
        ctx->form_scope == NULL || ctx->cgi_scope == NULL ||
        ctx->cookie_scope == NULL || ctx->request_scope == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Parse URL parameters into url scope */
ngx_int_t
cfml_parse_url_params(cfml_context_t *ctx)
{
    ngx_http_request_t *r = ctx->r;
    u_char *p, *start, *end;
    ngx_str_t key, value;

    if (r->args.len == 0) {
        return NGX_OK;
    }

    p = r->args.data;
    end = r->args.data + r->args.len;

    while (p < end) {
        /* Find key */
        start = p;
        while (p < end && *p != '=' && *p != '&') {
            p++;
        }
        key.data = start;
        key.len = p - start;

        if (p < end && *p == '=') {
            p++;
            /* Find value */
            start = p;
            while (p < end && *p != '&') {
                p++;
            }
            value.data = start;
            value.len = p - start;
        } else {
            value.data = (u_char *)"";
            value.len = 0;
        }

        if (*p == '&') {
            p++;
        }

        /* URL decode key and value */
        u_char *decoded_key = ngx_pnalloc(ctx->pool, key.len + 1);
        u_char *decoded_val = ngx_pnalloc(ctx->pool, value.len + 1);
        
        if (decoded_key == NULL || decoded_val == NULL) {
            return NGX_ERROR;
        }

        ngx_str_t dk, dv;
        dk.data = decoded_key;
        dk.len = ngx_copy(decoded_key, key.data, key.len) - decoded_key;
        
        dv.data = decoded_val;
        dv.len = ngx_copy(decoded_val, value.data, value.len) - decoded_val;

        /* URL decode (simplified) */
        /* TODO: Full URL decoding */

        cfml_struct_set(ctx->url_scope, &dk, cfml_create_string(ctx->pool, &dv));
    }

    return NGX_OK;
}

/* Parse form data */
ngx_int_t
cfml_parse_form_data(cfml_context_t *ctx)
{
    ngx_http_request_t *r = ctx->r;
    ngx_chain_t *cl;
    u_char *p, *start, *end;
    ngx_str_t key, value;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_OK;
    }

    /* Only handle application/x-www-form-urlencoded */
    if (r->headers_in.content_type == NULL ||
        ngx_strncasecmp(r->headers_in.content_type->value.data,
                        (u_char *)"application/x-www-form-urlencoded", 33) != 0) {
        return NGX_OK;
    }

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = cl->buf->pos;
        end = cl->buf->last;

        while (p < end) {
            start = p;
            while (p < end && *p != '=' && *p != '&') {
                p++;
            }
            key.data = start;
            key.len = p - start;

            if (p < end && *p == '=') {
                p++;
                start = p;
                while (p < end && *p != '&') {
                    p++;
                }
                value.data = start;
                value.len = p - start;
            } else {
                value.data = (u_char *)"";
                value.len = 0;
            }

            if (*p == '&') {
                p++;
            }

            cfml_struct_set(ctx->form_scope, &key, 
                            cfml_create_string(ctx->pool, &value));
        }
    }

    return NGX_OK;
}

/* Populate CGI scope */
ngx_int_t
cfml_populate_cgi_scope(cfml_context_t *ctx)
{
    ngx_http_request_t *r = ctx->r;
    ngx_str_t key, value;

    /* SERVER_NAME */
    ngx_str_set(&key, "server_name");
    if (r->headers_in.server.len > 0) {
        cfml_struct_set(ctx->cgi_scope, &key, 
                        cfml_create_string(ctx->pool, &r->headers_in.server));
    }

    /* REQUEST_METHOD */
    ngx_str_set(&key, "request_method");
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &r->method_name));

    /* REQUEST_URI */
    ngx_str_set(&key, "request_uri");
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &r->uri));

    /* QUERY_STRING */
    ngx_str_set(&key, "query_string");
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &r->args));

    /* SCRIPT_NAME */
    ngx_str_set(&key, "script_name");
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &r->uri));

    /* PATH_INFO */
    ngx_str_set(&key, "path_info");
    value.data = (u_char *)"";
    value.len = 0;
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &value));

    /* HTTP_HOST */
    ngx_str_set(&key, "http_host");
    if (r->headers_in.host != NULL) {
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &r->headers_in.host->value));
    }

    /* HTTP_USER_AGENT */
    ngx_str_set(&key, "http_user_agent");
    if (r->headers_in.user_agent != NULL) {
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &r->headers_in.user_agent->value));
    }

    /* HTTP_REFERER */
    ngx_str_set(&key, "http_referer");
    if (r->headers_in.referer != NULL) {
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &r->headers_in.referer->value));
    }

    /* CONTENT_TYPE */
    ngx_str_set(&key, "content_type");
    if (r->headers_in.content_type != NULL) {
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &r->headers_in.content_type->value));
    }

    /* CONTENT_LENGTH */
    ngx_str_set(&key, "content_length");
    if (r->headers_in.content_length != NULL) {
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &r->headers_in.content_length->value));
    }

    /* REMOTE_ADDR */
    ngx_str_set(&key, "remote_addr");
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &r->connection->addr_text));

    /* SERVER_PORT */
    ngx_str_set(&key, "server_port");
    value.data = ngx_pnalloc(ctx->pool, 8);
    if (value.data != NULL) {
        value.len = ngx_sprintf(value.data, "%ui", 
                                ngx_inet_get_port(r->connection->local_sockaddr)) 
                    - value.data;
        cfml_struct_set(ctx->cgi_scope, &key,
                        cfml_create_string(ctx->pool, &value));
    }

    /* HTTPS */
    ngx_str_set(&key, "https");
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        ngx_str_set(&value, "on");
    } else {
        ngx_str_set(&value, "off");
    }
#else
    ngx_str_set(&value, "off");
#endif
    cfml_struct_set(ctx->cgi_scope, &key,
                    cfml_create_string(ctx->pool, &value));

    return NGX_OK;
}

/* Parse cookies */
ngx_int_t
cfml_parse_cookies(cfml_context_t *ctx)
{
    ngx_http_request_t *r = ctx->r;
    ngx_table_elt_t *cookie;
    u_char *p, *start, *end;
    ngx_str_t key, value;

    /* Cookie header */
    cookie = r->headers_in.cookie;
    if (cookie == NULL) {
        return NGX_OK;
    }

    p = cookie->value.data;
    end = p + cookie->value.len;

    while (p < end) {
        /* Skip whitespace */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        
        start = p;
        
        /* Find = */
        while (p < end && *p != '=' && *p != ';') {
            p++;
        }
        
        key.data = start;
        key.len = p - start;
        
        if (*p == '=') {
            p++;
            start = p;
            
            /* Find end of value */
            while (p < end && *p != ';') {
                p++;
            }
            
            value.data = start;
            value.len = p - start;
        } else {
            value.data = (u_char *)"";
            value.len = 0;
        }
        
        if (key.len > 0) {
            cfml_struct_set(ctx->cookie_scope, &key, 
                           cfml_create_string(ctx->pool, &value));
        }
        
        if (*p == ';') {
            p++;
        }
    }

    return NGX_OK;
}


/* Initialize session */
ngx_int_t
cfml_init_session(cfml_context_t *ctx, ngx_msec_t timeout)
{
    /* Session scope is handled by the session module */
    ctx->session_scope = cfml_struct_new(ctx->pool);
    if (ctx->session_scope == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Get variable by name */
cfml_value_t *
cfml_get_variable(cfml_context_t *ctx, ngx_str_t *name)
{
    cfml_value_t *value;
    ngx_str_t scope_name, var_name;
    u_char *dot;

    /* Check for scope prefix */
    dot = (u_char *)ngx_strchr(name->data, '.');
    if (dot != NULL) {
        scope_name.data = name->data;
        scope_name.len = dot - name->data;
        var_name.data = dot + 1;
        var_name.len = name->len - scope_name.len - 1;

        cfml_scope_type_t scope = cfml_scope_from_name(&scope_name);
        if (scope != (cfml_scope_type_t)-1) {
            return cfml_get_scoped_variable(ctx, scope, &var_name);
        }
    }

    /* Search scopes in order */
    /* Local scope */
    value = cfml_struct_get(ctx->local_scope, name);
    if (value != NULL) {
        return value;
    }

    /* Arguments scope */
    value = cfml_struct_get(ctx->arguments_scope, name);
    if (value != NULL) {
        return value;
    }

    /* Variables scope */
    value = cfml_struct_get(ctx->variables_scope, name);
    if (value != NULL) {
        return value;
    }

    /* URL scope */
    value = cfml_struct_get(ctx->url_scope, name);
    if (value != NULL) {
        return value;
    }

    /* Form scope */
    value = cfml_struct_get(ctx->form_scope, name);
    if (value != NULL) {
        return value;
    }

    /* CGI scope */
    value = cfml_struct_get(ctx->cgi_scope, name);
    if (value != NULL) {
        return value;
    }

    return cfml_create_null(ctx->pool);
}

/* Get variable from specific scope */
cfml_value_t *
cfml_get_scoped_variable(cfml_context_t *ctx, cfml_scope_type_t scope,
                         ngx_str_t *name)
{
    cfml_struct_t *s = cfml_get_scope(ctx, scope);
    if (s == NULL) {
        return cfml_create_null(ctx->pool);
    }

    cfml_value_t *value = cfml_struct_get(s, name);
    return value ? value : cfml_create_null(ctx->pool);
}

/* Set variable */
ngx_int_t
cfml_set_variable(cfml_context_t *ctx, ngx_str_t *name, cfml_value_t *value)
{
    ngx_str_t scope_name, var_name;
    u_char *dot;

    /* Check for scope prefix */
    dot = (u_char *)ngx_strchr(name->data, '.');
    if (dot != NULL) {
        scope_name.data = name->data;
        scope_name.len = dot - name->data;
        var_name.data = dot + 1;
        var_name.len = name->len - scope_name.len - 1;

        cfml_scope_type_t scope = cfml_scope_from_name(&scope_name);
        if (scope != (cfml_scope_type_t)-1) {
            return cfml_set_scoped_variable(ctx, scope, &var_name, value);
        }
    }

    /* Default to variables scope */
    return cfml_struct_set(ctx->variables_scope, name, value);
}

/* Set variable in specific scope */
ngx_int_t
cfml_set_scoped_variable(cfml_context_t *ctx, cfml_scope_type_t scope,
                         ngx_str_t *name, cfml_value_t *value)
{
    cfml_struct_t *s = cfml_get_scope(ctx, scope);
    if (s == NULL) {
        return NGX_ERROR;
    }

    return cfml_struct_set(s, name, value);
}

/* Get scope struct */
cfml_struct_t *
cfml_get_scope(cfml_context_t *ctx, cfml_scope_type_t scope)
{
    switch (scope) {
    case CFML_SCOPE_VARIABLES:
        return ctx->variables_scope;
    case CFML_SCOPE_LOCAL:
        return ctx->local_scope;
    case CFML_SCOPE_ARGUMENTS:
        return ctx->arguments_scope;
    case CFML_SCOPE_URL:
        return ctx->url_scope;
    case CFML_SCOPE_FORM:
        return ctx->form_scope;
    case CFML_SCOPE_CGI:
        return ctx->cgi_scope;
    case CFML_SCOPE_COOKIE:
        return ctx->cookie_scope;
    case CFML_SCOPE_REQUEST:
        return ctx->request_scope;
    case CFML_SCOPE_SESSION:
        return ctx->session_scope;
    case CFML_SCOPE_APPLICATION:
        return ctx->application_scope;
    case CFML_SCOPE_SERVER:
        return ctx->server_scope;
    default:
        return NULL;
    }
}

/* Scope name from type */
cfml_scope_type_t
cfml_scope_from_name(ngx_str_t *name)
{
    static struct {
        ngx_str_t name;
        cfml_scope_type_t scope;
    } scopes[] = {
        { ngx_string("variables"), CFML_SCOPE_VARIABLES },
        { ngx_string("local"), CFML_SCOPE_LOCAL },
        { ngx_string("arguments"), CFML_SCOPE_ARGUMENTS },
        { ngx_string("url"), CFML_SCOPE_URL },
        { ngx_string("form"), CFML_SCOPE_FORM },
        { ngx_string("cgi"), CFML_SCOPE_CGI },
        { ngx_string("cookie"), CFML_SCOPE_COOKIE },
        { ngx_string("request"), CFML_SCOPE_REQUEST },
        { ngx_string("session"), CFML_SCOPE_SESSION },
        { ngx_string("application"), CFML_SCOPE_APPLICATION },
        { ngx_string("server"), CFML_SCOPE_SERVER },
        { ngx_string("this"), CFML_SCOPE_THIS },
        { ngx_string("super"), CFML_SCOPE_SUPER },
        { ngx_null_string, (cfml_scope_type_t)-1 }
    };

    ngx_uint_t i;
    for (i = 0; scopes[i].name.len > 0; i++) {
        if (name->len == scopes[i].name.len &&
            ngx_strncasecmp(name->data, scopes[i].name.data, name->len) == 0) {
            return scopes[i].scope;
        }
    }

    return (cfml_scope_type_t)-1;
}

/* Create null value */
cfml_value_t *
cfml_create_null(ngx_pool_t *pool)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_NULL;
    value->is_null = 1;
    value->pool = pool;
    return value;
}

/* Create boolean value */
cfml_value_t *
cfml_create_boolean(ngx_pool_t *pool, ngx_int_t val)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_BOOLEAN;
    value->data.boolean = val ? 1 : 0;
    value->pool = pool;
    return value;
}

/* Create integer value */
cfml_value_t *
cfml_create_integer(ngx_pool_t *pool, int64_t val)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_INTEGER;
    value->data.integer = val;
    value->pool = pool;
    return value;
}

/* Create float value */
cfml_value_t *
cfml_create_float(ngx_pool_t *pool, double val)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_FLOAT;
    value->data.floating = val;
    value->pool = pool;
    return value;
}

/* Create string value */
cfml_value_t *
cfml_create_string(ngx_pool_t *pool, ngx_str_t *val)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_STRING;
    value->data.string.len = val->len;
    value->data.string.data = ngx_pnalloc(pool, val->len + 1);
    if (value->data.string.data == NULL) {
        return NULL;
    }
    ngx_memcpy(value->data.string.data, val->data, val->len);
    value->data.string.data[val->len] = '\0';
    value->pool = pool;
    return value;
}

/* Create string value from C string */
cfml_value_t *
cfml_create_string_cstr(ngx_pool_t *pool, const char *val)
{
    ngx_str_t str;
    str.data = (u_char *)val;
    str.len = ngx_strlen(val);
    return cfml_create_string(pool, &str);
}

/* Create date value */
cfml_value_t *
cfml_create_date(ngx_pool_t *pool, time_t val)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_DATE;
    value->data.date.time = val;
    value->pool = pool;
    return value;
}

/* Create array value */
cfml_value_t *
cfml_create_array(ngx_pool_t *pool)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_ARRAY;
    value->data.array = cfml_array_new(pool, 16);
    if (value->data.array == NULL) {
        return NULL;
    }
    value->pool = pool;
    return value;
}

/* Create struct value */
cfml_value_t *
cfml_create_struct(ngx_pool_t *pool)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_STRUCT;
    value->data.structure = cfml_struct_new(pool);
    if (value->data.structure == NULL) {
        return NULL;
    }
    value->pool = pool;
    return value;
}

/* Create query value */
cfml_value_t *
cfml_create_query(ngx_pool_t *pool)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_QUERY;
    value->data.query = cfml_query_new(pool);
    if (value->data.query == NULL) {
        return NULL;
    }
    value->pool = pool;
    return value;
}

/* Create binary value */
cfml_value_t *
cfml_create_binary(ngx_pool_t *pool, u_char *data, size_t len)
{
    cfml_value_t *value = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (value == NULL) {
        return NULL;
    }
    value->type = CFML_TYPE_BINARY;
    value->data.binary.data = ngx_pnalloc(pool, len);
    if (value->data.binary.data == NULL) {
        return NULL;
    }
    ngx_memcpy(value->data.binary.data, data, len);
    value->data.binary.len = len;
    value->pool = pool;
    return value;
}

/* Array operations */
cfml_array_t *
cfml_array_new(ngx_pool_t *pool, size_t capacity)
{
    cfml_array_t *arr = ngx_pcalloc(pool, sizeof(cfml_array_t));
    if (arr == NULL) {
        return NULL;
    }
    arr->pool = pool;
    arr->items = ngx_array_create(pool, capacity, sizeof(cfml_value_t *));
    if (arr->items == NULL) {
        return NULL;
    }
    arr->capacity = capacity;
    return arr;
}

ngx_int_t
cfml_array_append(cfml_array_t *arr, cfml_value_t *value)
{
    cfml_value_t **slot = ngx_array_push(arr->items);
    if (slot == NULL) {
        return NGX_ERROR;
    }
    *slot = value;
    return NGX_OK;
}

cfml_value_t *
cfml_array_get(cfml_array_t *arr, ngx_uint_t index)
{
    cfml_value_t **items;
    if (arr == NULL || index >= arr->items->nelts) {
        return NULL;
    }
    items = arr->items->elts;
    return items[index];
}

ngx_int_t
cfml_array_set(cfml_array_t *arr, ngx_uint_t index, cfml_value_t *value)
{
    cfml_value_t **items;
    
    /* Expand array if necessary */
    while (index >= arr->items->nelts) {
        cfml_value_t **slot = ngx_array_push(arr->items);
        if (slot == NULL) {
            return NGX_ERROR;
        }
        *slot = cfml_create_null(arr->pool);
    }
    
    items = arr->items->elts;
    items[index] = value;
    return NGX_OK;
}

size_t
cfml_array_len(cfml_array_t *arr)
{
    return arr ? arr->items->nelts : 0;
}

/* Struct operations */
cfml_struct_t *
cfml_struct_new(ngx_pool_t *pool)
{
    cfml_struct_t *s = ngx_pcalloc(pool, sizeof(cfml_struct_t));
    if (s == NULL) {
        return NULL;
    }
    s->pool = pool;
    s->entries = ngx_array_create(pool, 16, sizeof(cfml_struct_entry_t));
    s->keys = ngx_array_create(pool, 16, sizeof(ngx_str_t));
    if (s->entries == NULL || s->keys == NULL) {
        return NULL;
    }
    return s;
}

ngx_int_t
cfml_struct_set(cfml_struct_t *s, ngx_str_t *key, cfml_value_t *value)
{
    cfml_struct_entry_t *entries, *entry;
    ngx_str_t *key_slot;
    ngx_uint_t i;

    if (s == NULL || key == NULL) {
        return NGX_ERROR;
    }

    /* Check if key exists */
    entries = s->entries->elts;
    for (i = 0; i < s->entries->nelts; i++) {
        if (entries[i].key.len == key->len &&
            ngx_strncasecmp(entries[i].key.data, key->data, key->len) == 0) {
            entries[i].value = value;
            return NGX_OK;
        }
    }

    /* Add new entry */
    entry = ngx_array_push(s->entries);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->key.len = key->len;
    entry->key.data = ngx_pnalloc(s->pool, key->len + 1);
    if (entry->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(entry->key.data, key->data, key->len);
    entry->key.data[key->len] = '\0';
    entry->value = value;

    /* Add to keys array */
    key_slot = ngx_array_push(s->keys);
    if (key_slot == NULL) {
        return NGX_ERROR;
    }
    *key_slot = entry->key;

    return NGX_OK;
}

cfml_value_t *
cfml_struct_get(cfml_struct_t *s, ngx_str_t *key)
{
    cfml_struct_entry_t *entries;
    ngx_uint_t i;

    if (s == NULL || key == NULL) {
        return NULL;
    }

    entries = s->entries->elts;
    for (i = 0; i < s->entries->nelts; i++) {
        if (entries[i].key.len == key->len &&
            ngx_strncasecmp(entries[i].key.data, key->data, key->len) == 0) {
            return entries[i].value;
        }
    }

    return NULL;
}

ngx_int_t
cfml_struct_exists(cfml_struct_t *s, ngx_str_t *key)
{
    return cfml_struct_get(s, key) != NULL;
}

size_t
cfml_struct_count(cfml_struct_t *s)
{
    return s ? s->entries->nelts : 0;
}

cfml_struct_t *
cfml_struct_copy(ngx_pool_t *pool, cfml_struct_t *s)
{
    cfml_struct_t *copy;
    cfml_struct_entry_t *entries;
    ngx_uint_t i;

    if (s == NULL) {
        return NULL;
    }

    copy = cfml_struct_new(pool);
    if (copy == NULL) {
        return NULL;
    }

    entries = s->entries->elts;
    for (i = 0; i < s->entries->nelts; i++) {
        cfml_struct_set(copy, &entries[i].key, entries[i].value);
    }

    return copy;
}

ngx_array_t *
cfml_struct_keys(cfml_struct_t *s)
{
    return s ? s->keys : NULL;
}

/* Query operations */
cfml_query_t *
cfml_query_new(ngx_pool_t *pool)
{
    cfml_query_t *q = ngx_pcalloc(pool, sizeof(cfml_query_t));
    if (q == NULL) {
        return NULL;
    }
    q->pool = pool;
    q->columns = ngx_array_create(pool, 8, sizeof(cfml_query_column_t));
    if (q->columns == NULL) {
        return NULL;
    }
    q->row_count = 0;
    q->current_row = 1;
    return q;
}

ngx_int_t
cfml_query_add_column(cfml_query_t *q, ngx_str_t *name, cfml_type_t type)
{
    cfml_query_column_t *col;

    col = ngx_array_push(q->columns);
    if (col == NULL) {
        return NGX_ERROR;
    }

    col->name = *name;
    col->type = type;
    col->data = ngx_array_create(q->pool, 32, sizeof(cfml_value_t *));
    if (col->data == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
cfml_query_add_row(cfml_query_t *q)
{
    cfml_query_column_t *cols;
    ngx_uint_t i;

    cols = q->columns->elts;
    for (i = 0; i < q->columns->nelts; i++) {
        cfml_value_t **slot = ngx_array_push(cols[i].data);
        if (slot == NULL) {
            return NGX_ERROR;
        }
        *slot = cfml_create_null(q->pool);
    }

    q->row_count++;
    return NGX_OK;
}

ngx_int_t
cfml_query_set_cell(cfml_query_t *q, ngx_str_t *column, ngx_uint_t row,
                    cfml_value_t *value)
{
    cfml_query_column_t *cols;
    cfml_value_t **cells;
    ngx_uint_t i;

    if (row < 1 || row > q->row_count) {
        return NGX_ERROR;
    }

    cols = q->columns->elts;
    for (i = 0; i < q->columns->nelts; i++) {
        if (cols[i].name.len == column->len &&
            ngx_strncasecmp(cols[i].name.data, column->data, column->len) == 0) {
            cells = cols[i].data->elts;
            cells[row - 1] = value;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

cfml_value_t *
cfml_query_get_cell(cfml_query_t *q, ngx_str_t *column, ngx_uint_t row)
{
    cfml_query_column_t *cols;
    cfml_value_t **cells;
    ngx_uint_t i;

    if (row < 1 || row > q->row_count) {
        return NULL;
    }

    cols = q->columns->elts;
    for (i = 0; i < q->columns->nelts; i++) {
        if (cols[i].name.len == column->len &&
            ngx_strncasecmp(cols[i].name.data, column->data, column->len) == 0) {
            cells = cols[i].data->elts;
            return cells[row - 1];
        }
    }

    return NULL;
}

size_t
cfml_query_row_count(cfml_query_t *q)
{
    return q ? q->row_count : 0;
}
