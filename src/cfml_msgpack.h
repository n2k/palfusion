/*
 * CFML MessagePack - Binary serialization format
 * Compact binary alternative to JSON
 */

#ifndef _CFML_MSGPACK_H_
#define _CFML_MSGPACK_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Serialize CFML value to MessagePack */
ngx_str_t *cfml_msgpack_encode(ngx_pool_t *pool, cfml_value_t *value);

/* Deserialize MessagePack to CFML value */
cfml_value_t *cfml_msgpack_decode(ngx_pool_t *pool, ngx_str_t *data);

/* CFML functions */
cfml_value_t *cfml_func_msgpackencode(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_msgpackdecode(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_MSGPACK_H_ */
