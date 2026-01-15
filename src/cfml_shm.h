/*
 * CFML Shared Memory - ngx_slab-based session and application storage
 */

#ifndef _CFML_SHM_H_
#define _CFML_SHM_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Shared memory value types (serializable) */
typedef enum {
    CFML_SHM_NULL = 0,
    CFML_SHM_BOOLEAN,
    CFML_SHM_INTEGER,
    CFML_SHM_FLOAT,
    CFML_SHM_STRING,
    CFML_SHM_DATE,
    CFML_SHM_STRUCT,
    CFML_SHM_ARRAY
} cfml_shm_type_t;

/* Serialized value header */
typedef struct {
    cfml_shm_type_t     type;
    uint32_t            size;
    uint32_t            data_offset;
} cfml_shm_value_header_t;

/* Session entry in shared memory */
typedef struct {
    u_char              id[64];          /* Session ID */
    ngx_msec_t          created;
    ngx_msec_t          last_accessed;
    ngx_msec_t          timeout;
    uint32_t            data_size;
    uint32_t            data_offset;     /* Offset to serialized struct */
    unsigned            active:1;
} cfml_shm_session_t;

/* Application entry in shared memory */
typedef struct {
    u_char              name[128];       /* Application name */
    ngx_msec_t          created;
    ngx_msec_t          last_accessed;
    ngx_msec_t          timeout;
    uint32_t            data_size;
    uint32_t            data_offset;
    unsigned            started:1;
} cfml_shm_application_t;

/* Shared memory zone context */
typedef struct {
    ngx_slab_pool_t     *shpool;
    ngx_rbtree_t        *session_tree;
    ngx_rbtree_node_t   *session_sentinel;
    ngx_rbtree_t        *app_tree;
    ngx_rbtree_node_t   *app_sentinel;
    ngx_atomic_t        *session_count;
    ngx_atomic_t        *app_count;
} cfml_shm_ctx_t;

/* Initialization */
ngx_int_t cfml_shm_init(ngx_shm_zone_t *zone, void *data);
ngx_int_t cfml_shm_init_zone(ngx_conf_t *cf, size_t size);

/* Session operations */
cfml_shm_session_t *cfml_shm_session_create(ngx_str_t *session_id, ngx_msec_t timeout);
cfml_shm_session_t *cfml_shm_session_find(ngx_str_t *session_id);
ngx_int_t cfml_shm_session_delete(ngx_str_t *session_id);
ngx_int_t cfml_shm_session_touch(ngx_str_t *session_id);
ngx_int_t cfml_shm_session_gc(ngx_msec_t current_time);

/* Session data operations */
ngx_int_t cfml_shm_session_set(ngx_str_t *session_id, ngx_str_t *key, cfml_value_t *value);
cfml_value_t *cfml_shm_session_get(ngx_pool_t *pool, ngx_str_t *session_id, ngx_str_t *key);
ngx_int_t cfml_shm_session_delete_key(ngx_str_t *session_id, ngx_str_t *key);
cfml_struct_t *cfml_shm_session_get_all(ngx_pool_t *pool, ngx_str_t *session_id);
ngx_int_t cfml_shm_session_set_all(ngx_str_t *session_id, cfml_struct_t *data);

/* Application operations */
cfml_shm_application_t *cfml_shm_app_create(ngx_str_t *app_name, ngx_msec_t timeout);
cfml_shm_application_t *cfml_shm_app_find(ngx_str_t *app_name);
ngx_int_t cfml_shm_app_delete(ngx_str_t *app_name);
ngx_int_t cfml_shm_app_touch(ngx_str_t *app_name);

/* Application data operations */
ngx_int_t cfml_shm_app_set(ngx_str_t *app_name, ngx_str_t *key, cfml_value_t *value);
cfml_value_t *cfml_shm_app_get(ngx_pool_t *pool, ngx_str_t *app_name, ngx_str_t *key);
ngx_int_t cfml_shm_app_delete_key(ngx_str_t *app_name, ngx_str_t *key);
cfml_struct_t *cfml_shm_app_get_all(ngx_pool_t *pool, ngx_str_t *app_name);
ngx_int_t cfml_shm_app_set_all(ngx_str_t *app_name, cfml_struct_t *data);

/* Serialization */
ngx_int_t cfml_shm_serialize_value(ngx_slab_pool_t *shpool, cfml_value_t *value,
                                    u_char **data, uint32_t *size);
cfml_value_t *cfml_shm_deserialize_value(ngx_pool_t *pool, u_char *data, uint32_t size);
ngx_int_t cfml_shm_serialize_struct(ngx_slab_pool_t *shpool, cfml_struct_t *s,
                                     u_char **data, uint32_t *size);
cfml_struct_t *cfml_shm_deserialize_struct(ngx_pool_t *pool, u_char *data, uint32_t size);

/* Locking */
void cfml_shm_lock(void);
void cfml_shm_unlock(void);

/* Statistics */
ngx_uint_t cfml_shm_session_count(void);
ngx_uint_t cfml_shm_app_count(void);
size_t cfml_shm_used_size(void);
size_t cfml_shm_free_size(void);

#endif /* _CFML_SHM_H_ */
