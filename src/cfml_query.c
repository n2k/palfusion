/*
 * CFML Query - Query-of-Queries and SQL utilities
 * Note: Database connection functions are in cfml_database.c
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_query.h"
#include "cfml_variables.h"

/* Query-of-Queries execution - operates on in-memory query objects */
ngx_int_t 
cfml_qoq_execute(cfml_context_t *ctx, ngx_str_t *sql, cfml_query_t **result) {
    /* TODO: Implement QoQ SQL parser */
    (void)ctx;
    (void)sql;
    *result = NULL;
    return NGX_DECLINED;
}

ngx_int_t cfml_sql_parse(ngx_pool_t *pool, ngx_str_t *sql, ngx_array_t **params) { return NGX_OK; }
ngx_int_t cfml_sql_validate(ngx_str_t *sql) { return NGX_OK; }

ngx_int_t
cfml_sql_escape_string(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *output)
{
    /* Simple escape - replace ' with '' */
    u_char *p, *end, *out;
    size_t count = 0;

    p = input->data;
    end = input->data + input->len;

    while (p < end) {
        if (*p == '\'') count++;
        p++;
    }

    output->len = input->len + count;
    output->data = ngx_pnalloc(pool, output->len + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }

    p = input->data;
    out = output->data;
    while (p < end) {
        if (*p == '\'') {
            *out++ = '\'';
        }
        *out++ = *p++;
    }
    *out = '\0';

    return NGX_OK;
}

ngx_int_t
cfml_parse_connection_string(ngx_pool_t *pool, ngx_str_t *conn_str,
                             cfml_datasource_t *ds)
{
    /* Parse: driver://user:pass@host:port/database */
    u_char *p, *start;
    
    p = conn_str->data;
    start = p;
    
    /* Find driver */
    while (*p && *p != ':') p++;
    ds->driver.data = start;
    ds->driver.len = p - start;
    
    if (*p == ':') p++;
    if (*p == '/') p++;
    if (*p == '/') p++;
    
    /* Find user */
    start = p;
    while (*p && *p != ':' && *p != '@') p++;
    ds->username.data = start;
    ds->username.len = p - start;
    
    /* Find password */
    if (*p == ':') {
        p++;
        start = p;
        while (*p && *p != '@') p++;
        ds->password.data = start;
        ds->password.len = p - start;
    }
    
    if (*p == '@') p++;
    
    /* Find host */
    start = p;
    while (*p && *p != ':' && *p != '/') p++;
    ds->host.data = start;
    ds->host.len = p - start;
    
    /* Find port */
    if (*p == ':') {
        p++;
        ds->port = ngx_atoi(p, 5);
        while (*p && *p != '/') p++;
    }
    
    if (*p == '/') p++;
    
    /* Find database */
    ds->database.data = p;
    ds->database.len = conn_str->len - (p - conn_str->data);
    
    return NGX_OK;
}
