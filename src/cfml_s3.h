/*
 * CFML S3 - S3-compatible object storage client
 * Works with AWS S3, MinIO, Cloudflare R2, etc.
 */

#ifndef _CFML_S3_H_
#define _CFML_S3_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* S3 client configuration */
typedef struct {
    ngx_str_t           endpoint;
    ngx_str_t           region;
    ngx_str_t           access_key;
    ngx_str_t           secret_key;
    ngx_str_t           bucket;
    unsigned            path_style:1;   /* Path-style vs virtual-hosted */
} cfml_s3_config_t;

/* S3 object metadata */
typedef struct {
    ngx_str_t           key;
    ngx_str_t           etag;
    size_t              size;
    time_t              last_modified;
    ngx_str_t           content_type;
    ngx_str_t           storage_class;
} cfml_s3_object_t;

/* Initialize S3 client */
ngx_int_t cfml_s3_init(ngx_pool_t *pool, cfml_s3_config_t *config);

/* Put object */
ngx_int_t cfml_s3_put(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key, ngx_str_t *data, ngx_str_t *content_type);

/* Get object */
ngx_str_t *cfml_s3_get(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key);

/* Delete object */
ngx_int_t cfml_s3_delete(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key);

/* List objects */
ngx_array_t *cfml_s3_list(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *prefix, ngx_uint_t max_keys);

/* Generate presigned URL */
ngx_str_t *cfml_s3_presign(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key, ngx_int_t expires_seconds, ngx_int_t is_put);

/* CFML functions */
cfml_value_t *cfml_func_s3put(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_s3get(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_s3delete(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_s3list(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_s3presign(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_S3_H_ */
