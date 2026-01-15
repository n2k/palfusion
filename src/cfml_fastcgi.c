/*
 * CFML FastCGI - Proxy to external CFML engines (stub)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_fastcgi.h"

ngx_int_t cfml_fastcgi_init(ngx_cycle_t *cycle) { return NGX_OK; }
void cfml_fastcgi_cleanup(ngx_cycle_t *cycle) { }

ngx_int_t
cfml_fastcgi_proxy(cfml_context_t *ctx, ngx_str_t *address)
{
    /* Full implementation would proxy to Lucee/Adobe CF */
    return NGX_DECLINED;
}

ngx_int_t
cfml_fastcgi_query(cfml_context_t *ctx, ngx_str_t *address,
                   ngx_str_t *datasource, ngx_str_t *sql,
                   cfml_query_t **result)
{
    return NGX_DECLINED;
}

ngx_int_t
cfml_fastcgi_invoke(cfml_context_t *ctx, ngx_str_t *address,
                    ngx_str_t *component, ngx_str_t *method,
                    ngx_array_t *args, cfml_value_t **result)
{
    return NGX_DECLINED;
}

ngx_int_t cfml_fastcgi_get_connection(ngx_str_t *address, void **conn) { return NGX_DECLINED; }
ngx_int_t cfml_fastcgi_release_connection(void *conn) { return NGX_OK; }
