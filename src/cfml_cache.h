/*
 * CFML Cache - Template caching
 */

#ifndef _CFML_CACHE_H_
#define _CFML_CACHE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Cache initialization */
ngx_int_t cfml_cache_init(ngx_cycle_t *cycle);
void cfml_cache_cleanup(ngx_cycle_t *cycle);

/* Template cache operations */
cfml_template_t *cfml_cache_get(ngx_str_t *path);
ngx_int_t cfml_cache_put(ngx_str_t *path, cfml_template_t *tmpl);
ngx_int_t cfml_cache_invalidate(ngx_str_t *path);
ngx_int_t cfml_cache_clear(void);

/* Check if template needs recompilation */
ngx_int_t cfml_cache_is_stale(ngx_str_t *path, cfml_template_t *tmpl);

/* Output cache (for cfcache tag) */
ngx_int_t cfml_output_cache_get(ngx_str_t *key, ngx_str_t *output);
ngx_int_t cfml_output_cache_put(ngx_str_t *key, ngx_str_t *output, ngx_msec_t timeout);
ngx_int_t cfml_output_cache_delete(ngx_str_t *key);

/* Cache statistics */
typedef struct {
    size_t          entries;
    size_t          hits;
    size_t          misses;
    size_t          memory_used;
} cfml_cache_stats_t;

ngx_int_t cfml_cache_get_stats(cfml_cache_stats_t *stats);

#endif /* _CFML_CACHE_H_ */
