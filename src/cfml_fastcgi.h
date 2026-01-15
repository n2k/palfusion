/*
 * CFML FastCGI - Proxy to external CFML engines
 */

#ifndef _CFML_FASTCGI_H_
#define _CFML_FASTCGI_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* FastCGI operations */
ngx_int_t cfml_fastcgi_init(ngx_cycle_t *cycle);
void cfml_fastcgi_cleanup(ngx_cycle_t *cycle);

/* Proxy request to external CFML engine */
ngx_int_t cfml_fastcgi_proxy(cfml_context_t *ctx, ngx_str_t *address);

/* Execute specific operations via FastCGI */
ngx_int_t cfml_fastcgi_query(cfml_context_t *ctx, ngx_str_t *address,
                             ngx_str_t *datasource, ngx_str_t *sql,
                             cfml_query_t **result);

ngx_int_t cfml_fastcgi_invoke(cfml_context_t *ctx, ngx_str_t *address,
                              ngx_str_t *component, ngx_str_t *method,
                              ngx_array_t *args, cfml_value_t **result);

/* Connection pool */
ngx_int_t cfml_fastcgi_get_connection(ngx_str_t *address, void **conn);
ngx_int_t cfml_fastcgi_release_connection(void *conn);

#endif /* _CFML_FASTCGI_H_ */
