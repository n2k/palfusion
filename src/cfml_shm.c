/*
 * CFML Shared Memory - ngx_slab-based session and application storage
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_shm.h"
#include "cfml_variables.h"

static cfml_shm_ctx_t *cfml_shm_ctx = NULL;
static ngx_shm_zone_t *cfml_shm_zone = NULL;

/* Red-black tree node for sessions */
typedef struct {
    ngx_rbtree_node_t   node;
    ngx_str_t           key;
    cfml_shm_session_t  *session;
} cfml_shm_session_node_t;

/* Red-black tree node for applications */
typedef struct {
    ngx_rbtree_node_t   node;
    ngx_str_t           key;
    cfml_shm_application_t *app;
} cfml_shm_app_node_t;

static void
cfml_shm_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    cfml_shm_session_node_t *n, *t;

    for (;;) {
        n = (cfml_shm_session_node_t *)node;
        t = (cfml_shm_session_node_t *)temp;

        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;
        } else if (n->key.len != t->key.len) {
            p = (n->key.len < t->key.len) ? &temp->left : &temp->right;
        } else {
            p = (ngx_memcmp(n->key.data, t->key.data, n->key.len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

ngx_int_t
cfml_shm_init(ngx_shm_zone_t *zone, void *data)
{
    cfml_shm_ctx_t *octx = data;
    cfml_shm_ctx_t *ctx;
    ngx_slab_pool_t *shpool;
    
    shpool = (ngx_slab_pool_t *)zone->shm.addr;
    
    if (octx) {
        /* Reusing existing zone */
        ctx = octx;
        zone->data = ctx;
        cfml_shm_ctx = ctx;
        return NGX_OK;
    }
    
    /* Allocate context */
    ctx = ngx_slab_alloc(shpool, sizeof(cfml_shm_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    
    ctx->shpool = shpool;
    
    /* Initialize session tree */
    ctx->session_tree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    ctx->session_sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (ctx->session_tree == NULL || ctx->session_sentinel == NULL) {
        return NGX_ERROR;
    }
    ngx_rbtree_init(ctx->session_tree, ctx->session_sentinel,
                    cfml_shm_rbtree_insert_value);
    
    /* Initialize application tree */
    ctx->app_tree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    ctx->app_sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (ctx->app_tree == NULL || ctx->app_sentinel == NULL) {
        return NGX_ERROR;
    }
    ngx_rbtree_init(ctx->app_tree, ctx->app_sentinel,
                    cfml_shm_rbtree_insert_value);
    
    /* Initialize counters */
    ctx->session_count = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t));
    ctx->app_count = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t));
    if (ctx->session_count == NULL || ctx->app_count == NULL) {
        return NGX_ERROR;
    }
    *ctx->session_count = 0;
    *ctx->app_count = 0;
    
    zone->data = ctx;
    cfml_shm_ctx = ctx;
    cfml_shm_zone = zone;
    
    return NGX_OK;
}

ngx_int_t
cfml_shm_init_zone(ngx_conf_t *cf, size_t size)
{
    ngx_shm_zone_t *zone;
    ngx_str_t name = ngx_string("cfml_shared_zone");
    
    /* Use a unique module tag for this shared memory zone */
    static ngx_str_t cfml_shm_tag = ngx_string("cfml_shm");
    zone = ngx_shared_memory_add(cf, &name, size, &cfml_shm_tag);
    if (zone == NULL) {
        return NGX_ERROR;
    }
    
    zone->init = cfml_shm_init;
    zone->data = NULL;
    
    cfml_shm_zone = zone;
    
    return NGX_OK;
}

void
cfml_shm_lock(void)
{
    if (cfml_shm_ctx && cfml_shm_ctx->shpool) {
        ngx_shmtx_lock(&cfml_shm_ctx->shpool->mutex);
    }
}

void
cfml_shm_unlock(void)
{
    if (cfml_shm_ctx && cfml_shm_ctx->shpool) {
        ngx_shmtx_unlock(&cfml_shm_ctx->shpool->mutex);
    }
}

static uint32_t
cfml_shm_hash(ngx_str_t *key)
{
    return ngx_crc32_long(key->data, key->len);
}

static cfml_shm_session_node_t *
cfml_shm_session_lookup(ngx_str_t *session_id)
{
    ngx_rbtree_node_t *node, *sentinel;
    cfml_shm_session_node_t *n;
    uint32_t hash;
    ngx_int_t rc;
    
    if (cfml_shm_ctx == NULL) {
        return NULL;
    }
    
    hash = cfml_shm_hash(session_id);
    node = cfml_shm_ctx->session_tree->root;
    sentinel = cfml_shm_ctx->session_tree->sentinel;
    
    while (node != sentinel) {
        n = (cfml_shm_session_node_t *)node;
        
        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }
        
        if (n->key.len != session_id->len) {
            node = (session_id->len < n->key.len) ? node->left : node->right;
            continue;
        }
        
        rc = ngx_memcmp(session_id->data, n->key.data, session_id->len);
        
        if (rc == 0) {
            return n;
        }
        
        node = (rc < 0) ? node->left : node->right;
    }
    
    return NULL;
}

cfml_shm_session_t *
cfml_shm_session_create(ngx_str_t *session_id, ngx_msec_t timeout)
{
    cfml_shm_session_node_t *node;
    cfml_shm_session_t *session;
    ngx_slab_pool_t *shpool;
    
    if (cfml_shm_ctx == NULL) {
        return NULL;
    }
    
    shpool = cfml_shm_ctx->shpool;
    
    cfml_shm_lock();
    
    /* Check if already exists */
    node = cfml_shm_session_lookup(session_id);
    if (node != NULL) {
        cfml_shm_unlock();
        return node->session;
    }
    
    /* Allocate node */
    node = ngx_slab_alloc_locked(shpool, sizeof(cfml_shm_session_node_t));
    if (node == NULL) {
        cfml_shm_unlock();
        return NULL;
    }
    
    /* Allocate session */
    session = ngx_slab_alloc_locked(shpool, sizeof(cfml_shm_session_t));
    if (session == NULL) {
        ngx_slab_free_locked(shpool, node);
        cfml_shm_unlock();
        return NULL;
    }
    
    /* Allocate key data */
    node->key.data = ngx_slab_alloc_locked(shpool, session_id->len);
    if (node->key.data == NULL) {
        ngx_slab_free_locked(shpool, session);
        ngx_slab_free_locked(shpool, node);
        cfml_shm_unlock();
        return NULL;
    }
    
    /* Initialize */
    ngx_memcpy(node->key.data, session_id->data, session_id->len);
    node->key.len = session_id->len;
    node->node.key = cfml_shm_hash(session_id);
    node->session = session;
    
    ngx_memcpy(session->id, session_id->data,
               session_id->len > 63 ? 63 : session_id->len);
    session->created = ngx_current_msec;
    session->last_accessed = ngx_current_msec;
    session->timeout = timeout;
    session->active = 1;
    session->data_size = 0;
    session->data_offset = 0;
    
    /* Insert into tree */
    ngx_rbtree_insert(cfml_shm_ctx->session_tree, &node->node);
    ngx_atomic_fetch_add(cfml_shm_ctx->session_count, 1);
    
    cfml_shm_unlock();
    
    return session;
}

cfml_shm_session_t *
cfml_shm_session_find(ngx_str_t *session_id)
{
    cfml_shm_session_node_t *node;
    cfml_shm_session_t *session = NULL;
    
    cfml_shm_lock();
    
    node = cfml_shm_session_lookup(session_id);
    if (node != NULL && node->session->active) {
        /* Check expiration */
        if (ngx_current_msec - node->session->last_accessed < node->session->timeout) {
            session = node->session;
        }
    }
    
    cfml_shm_unlock();
    
    return session;
}

ngx_int_t
cfml_shm_session_delete(ngx_str_t *session_id)
{
    cfml_shm_session_node_t *node;
    ngx_slab_pool_t *shpool;
    
    if (cfml_shm_ctx == NULL) {
        return NGX_ERROR;
    }
    
    shpool = cfml_shm_ctx->shpool;
    
    cfml_shm_lock();
    
    node = cfml_shm_session_lookup(session_id);
    if (node == NULL) {
        cfml_shm_unlock();
        return NGX_DECLINED;
    }
    
    /* Remove from tree */
    ngx_rbtree_delete(cfml_shm_ctx->session_tree, &node->node);
    
    /* Free session data if any */
    if (node->session->data_size > 0) {
        /* Data is at offset from shpool base */
        u_char *data = (u_char *)shpool + node->session->data_offset;
        ngx_slab_free_locked(shpool, data);
    }
    
    /* Free structures */
    ngx_slab_free_locked(shpool, node->session);
    ngx_slab_free_locked(shpool, node->key.data);
    ngx_slab_free_locked(shpool, node);
    
    ngx_atomic_fetch_add(cfml_shm_ctx->session_count, -1);
    
    cfml_shm_unlock();
    
    return NGX_OK;
}

ngx_int_t
cfml_shm_session_touch(ngx_str_t *session_id)
{
    cfml_shm_session_node_t *node;
    
    cfml_shm_lock();
    
    node = cfml_shm_session_lookup(session_id);
    if (node != NULL) {
        node->session->last_accessed = ngx_current_msec;
    }
    
    cfml_shm_unlock();
    
    return node != NULL ? NGX_OK : NGX_DECLINED;
}

ngx_int_t
cfml_shm_session_gc(ngx_msec_t current_time)
{
    /* TODO: Walk tree and remove expired sessions */
    return NGX_OK;
}

/* Serialization helpers */
ngx_int_t
cfml_shm_serialize_value(ngx_slab_pool_t *shpool, cfml_value_t *value,
                          u_char **data, uint32_t *size)
{
    cfml_shm_value_header_t header;
    u_char *buf, *p;
    uint32_t total_size;
    
    if (value == NULL) {
        header.type = CFML_SHM_NULL;
        header.size = 0;
        header.data_offset = 0;
        
        total_size = sizeof(header);
        buf = ngx_slab_alloc_locked(shpool, total_size);
        if (buf == NULL) {
            return NGX_ERROR;
        }
        
        ngx_memcpy(buf, &header, sizeof(header));
        *data = buf;
        *size = total_size;
        return NGX_OK;
    }
    
    switch (value->type) {
    case CFML_TYPE_NULL:
        header.type = CFML_SHM_NULL;
        header.size = 0;
        break;
        
    case CFML_TYPE_BOOLEAN:
        header.type = CFML_SHM_BOOLEAN;
        header.size = sizeof(ngx_flag_t);
        break;
        
    case CFML_TYPE_INTEGER:
        header.type = CFML_SHM_INTEGER;
        header.size = sizeof(int64_t);
        break;
        
    case CFML_TYPE_FLOAT:
        header.type = CFML_SHM_FLOAT;
        header.size = sizeof(double);
        break;
        
    case CFML_TYPE_STRING:
        header.type = CFML_SHM_STRING;
        header.size = sizeof(uint32_t) + value->data.string.len;
        break;
        
    case CFML_TYPE_DATE:
        header.type = CFML_SHM_DATE;
        header.size = sizeof(time_t);
        break;
        
    default:
        /* Complex types not fully supported yet */
        header.type = CFML_SHM_NULL;
        header.size = 0;
        break;
    }
    
    header.data_offset = sizeof(header);
    total_size = sizeof(header) + header.size;
    
    buf = ngx_slab_alloc_locked(shpool, total_size);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    
    p = buf;
    ngx_memcpy(p, &header, sizeof(header));
    p += sizeof(header);
    
    switch (value->type) {
    case CFML_TYPE_BOOLEAN:
        ngx_memcpy(p, &value->data.boolean, sizeof(ngx_flag_t));
        break;
        
    case CFML_TYPE_INTEGER:
        ngx_memcpy(p, &value->data.integer, sizeof(int64_t));
        break;
        
    case CFML_TYPE_FLOAT:
        ngx_memcpy(p, &value->data.floating, sizeof(double));
        break;
        
    case CFML_TYPE_STRING:
        {
            uint32_t len = value->data.string.len;
            ngx_memcpy(p, &len, sizeof(uint32_t));
            p += sizeof(uint32_t);
            ngx_memcpy(p, value->data.string.data, len);
        }
        break;
        
    case CFML_TYPE_DATE:
        ngx_memcpy(p, &value->data.date.time, sizeof(time_t));
        break;
        
    default:
        break;
    }
    
    *data = buf;
    *size = total_size;
    
    return NGX_OK;
}

cfml_value_t *
cfml_shm_deserialize_value(ngx_pool_t *pool, u_char *data, uint32_t size)
{
    cfml_shm_value_header_t *header;
    u_char *p;
    
    if (data == NULL || size < sizeof(cfml_shm_value_header_t)) {
        return NULL;
    }
    
    header = (cfml_shm_value_header_t *)data;
    p = data + header->data_offset;
    
    switch (header->type) {
    case CFML_SHM_NULL:
        return cfml_create_null(pool);
        
    case CFML_SHM_BOOLEAN:
        {
            ngx_flag_t val;
            ngx_memcpy(&val, p, sizeof(ngx_flag_t));
            return cfml_create_boolean(pool, val);
        }
        
    case CFML_SHM_INTEGER:
        {
            int64_t val;
            ngx_memcpy(&val, p, sizeof(int64_t));
            return cfml_create_integer(pool, val);
        }
        
    case CFML_SHM_FLOAT:
        {
            double val;
            ngx_memcpy(&val, p, sizeof(double));
            return cfml_create_float(pool, val);
        }
        
    case CFML_SHM_STRING:
        {
            uint32_t len;
            ngx_str_t str;
            ngx_memcpy(&len, p, sizeof(uint32_t));
            str.len = len;
            str.data = p + sizeof(uint32_t);
            return cfml_create_string(pool, &str);
        }
        
    case CFML_SHM_DATE:
        {
            time_t val;
            ngx_memcpy(&val, p, sizeof(time_t));
            return cfml_create_date(pool, val);
        }
        
    default:
        return cfml_create_null(pool);
    }
}

ngx_int_t
cfml_shm_session_set(ngx_str_t *session_id, ngx_str_t *key, cfml_value_t *value)
{
    /* Simplified: would need to manage a key-value store per session */
    cfml_shm_session_t *session = cfml_shm_session_find(session_id);
    if (session == NULL) {
        return NGX_ERROR;
    }
    
    /* TODO: Implement per-key storage in shared memory */
    return NGX_OK;
}

cfml_value_t *
cfml_shm_session_get(ngx_pool_t *pool, ngx_str_t *session_id, ngx_str_t *key)
{
    /* TODO: Implement per-key retrieval */
    return NULL;
}

/* Application operations mirror session operations */
cfml_shm_application_t *
cfml_shm_app_create(ngx_str_t *app_name, ngx_msec_t timeout)
{
    /* Similar to session_create */
    return NULL;
}

cfml_shm_application_t *
cfml_shm_app_find(ngx_str_t *app_name)
{
    return NULL;
}

ngx_int_t
cfml_shm_app_set(ngx_str_t *app_name, ngx_str_t *key, cfml_value_t *value)
{
    return NGX_OK;
}

cfml_value_t *
cfml_shm_app_get(ngx_pool_t *pool, ngx_str_t *app_name, ngx_str_t *key)
{
    return NULL;
}

/* Statistics */
ngx_uint_t
cfml_shm_session_count(void)
{
    if (cfml_shm_ctx == NULL || cfml_shm_ctx->session_count == NULL) {
        return 0;
    }
    return *cfml_shm_ctx->session_count;
}

ngx_uint_t
cfml_shm_app_count(void)
{
    if (cfml_shm_ctx == NULL || cfml_shm_ctx->app_count == NULL) {
        return 0;
    }
    return *cfml_shm_ctx->app_count;
}
