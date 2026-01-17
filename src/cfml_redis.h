/*
 * CFML Redis/Valkey - Native Redis client integration
 * Session storage, caching, pub/sub
 */

#ifndef _CFML_REDIS_H_
#define _CFML_REDIS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Redis response types */
typedef enum {
    CFML_REDIS_STRING = '+',
    CFML_REDIS_ERROR = '-',
    CFML_REDIS_INTEGER = ':',
    CFML_REDIS_BULK = '$',
    CFML_REDIS_ARRAY = '*',
    CFML_REDIS_NULL = '_',
    CFML_REDIS_BOOL = '#',
    CFML_REDIS_DOUBLE = ',',
    CFML_REDIS_MAP = '%',
    CFML_REDIS_SET = '~'
} cfml_redis_type_t;

/* Redis connection state */
typedef enum {
    CFML_REDIS_DISCONNECTED = 0,
    CFML_REDIS_CONNECTING,
    CFML_REDIS_CONNECTED,
    CFML_REDIS_AUTH_REQUIRED,
    CFML_REDIS_AUTHENTICATED,
    CFML_REDIS_ERROR_STATE
} cfml_redis_state_t;

/* Redis response */
typedef struct cfml_redis_reply_s cfml_redis_reply_t;
struct cfml_redis_reply_s {
    cfml_redis_type_t   type;
    int64_t             integer;
    double              dval;
    ngx_str_t           str;
    ngx_array_t         *elements;      /* Array of cfml_redis_reply_t* */
    ngx_pool_t          *pool;
};

/* Redis connection */
typedef struct {
    ngx_str_t               host;
    ngx_uint_t              port;
    ngx_str_t               password;
    ngx_str_t               username;      /* Redis 6.0+ ACL */
    ngx_int_t               db;
    ngx_msec_t              timeout;
    ngx_msec_t              connect_timeout;
    
    /* Connection state */
    ngx_socket_t            socket;
    cfml_redis_state_t      state;
    
    /* SSL/TLS */
    unsigned                ssl:1;
    void                    *ssl_conn;      /* SSL* */
    
    /* Buffers */
    u_char                  *recv_buf;
    size_t                  recv_buf_size;
    size_t                  recv_buf_pos;
    
    /* Pool management */
    ngx_pool_t              *pool;
    ngx_queue_t             queue;
    ngx_msec_t              last_used;
    unsigned                in_use:1;
    unsigned                in_transaction:1;
} cfml_redis_conn_t;

/* Redis connection pool */
typedef struct {
    ngx_str_t               name;
    ngx_str_t               host;
    ngx_uint_t              port;
    ngx_str_t               password;
    ngx_str_t               username;
    ngx_int_t               db;
    ngx_msec_t              timeout;
    unsigned                ssl:1;
    
    ngx_uint_t              max_connections;
    ngx_uint_t              min_connections;
    ngx_msec_t              keepalive_timeout;
    
    ngx_queue_t             free_connections;
    ngx_queue_t             active_connections;
    ngx_uint_t              connection_count;
    
    ngx_pool_t              *pool;
} cfml_redis_pool_t;

/* Redis configuration (from nginx config) */
typedef struct {
    ngx_str_t               default_server;
    ngx_uint_t              default_port;
    ngx_str_t               default_password;
    ngx_int_t               default_db;
    ngx_msec_t              default_timeout;
    ngx_uint_t              pool_size;
    unsigned                enabled:1;
    unsigned                session_storage:1;  /* Use Redis for sessions */
} cfml_redis_conf_t;

/*
 * Connection Management
 */

/* Initialize Redis module */
ngx_int_t cfml_redis_init(ngx_cycle_t *cycle);

/* Cleanup Redis module */
void cfml_redis_cleanup(ngx_cycle_t *cycle);

/* Create connection pool */
cfml_redis_pool_t *cfml_redis_pool_create(ngx_pool_t *pool, ngx_str_t *host,
    ngx_uint_t port, ngx_str_t *password, ngx_int_t db);

/* Get connection from pool */
cfml_redis_conn_t *cfml_redis_get_connection(cfml_redis_pool_t *pool);

/* Return connection to pool */
void cfml_redis_release_connection(cfml_redis_pool_t *pool, cfml_redis_conn_t *conn);

/* Create new connection */
cfml_redis_conn_t *cfml_redis_connect(ngx_pool_t *pool, ngx_str_t *host,
    ngx_uint_t port, ngx_msec_t timeout);

/* Authenticate */
ngx_int_t cfml_redis_auth(cfml_redis_conn_t *conn, ngx_str_t *password,
    ngx_str_t *username);

/* Select database */
ngx_int_t cfml_redis_select(cfml_redis_conn_t *conn, ngx_int_t db);

/* Close connection */
void cfml_redis_close(cfml_redis_conn_t *conn);

/* Ping */
ngx_int_t cfml_redis_ping(cfml_redis_conn_t *conn);

/*
 * Command Execution
 */

/* Execute command with varargs */
cfml_redis_reply_t *cfml_redis_command(cfml_redis_conn_t *conn, 
    ngx_pool_t *pool, const char *format, ...);

/* Execute command with array of arguments */
cfml_redis_reply_t *cfml_redis_command_argv(cfml_redis_conn_t *conn,
    ngx_pool_t *pool, ngx_uint_t argc, ngx_str_t *argv);

/* Free reply */
void cfml_redis_free_reply(cfml_redis_reply_t *reply);

/*
 * String Commands
 */

ngx_int_t cfml_redis_set(cfml_redis_conn_t *conn, ngx_str_t *key, 
    ngx_str_t *value, ngx_int_t ttl);
ngx_str_t *cfml_redis_get(cfml_redis_conn_t *conn, ngx_pool_t *pool, 
    ngx_str_t *key);
ngx_int_t cfml_redis_del(cfml_redis_conn_t *conn, ngx_str_t *key);
ngx_int_t cfml_redis_exists(cfml_redis_conn_t *conn, ngx_str_t *key);
ngx_int_t cfml_redis_expire(cfml_redis_conn_t *conn, ngx_str_t *key, 
    ngx_int_t seconds);
ngx_int_t cfml_redis_ttl(cfml_redis_conn_t *conn, ngx_str_t *key);
ngx_int_t cfml_redis_incr(cfml_redis_conn_t *conn, ngx_str_t *key);
ngx_int_t cfml_redis_decr(cfml_redis_conn_t *conn, ngx_str_t *key);
ngx_int_t cfml_redis_incrby(cfml_redis_conn_t *conn, ngx_str_t *key, int64_t amount);

/*
 * Hash Commands
 */

ngx_int_t cfml_redis_hset(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *field, ngx_str_t *value);
ngx_str_t *cfml_redis_hget(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key, ngx_str_t *field);
cfml_struct_t *cfml_redis_hgetall(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key);
ngx_int_t cfml_redis_hdel(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *field);
ngx_int_t cfml_redis_hexists(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *field);

/*
 * List Commands
 */

ngx_int_t cfml_redis_lpush(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *value);
ngx_int_t cfml_redis_rpush(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *value);
ngx_str_t *cfml_redis_lpop(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key);
ngx_str_t *cfml_redis_rpop(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key);
ngx_array_t *cfml_redis_lrange(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key, ngx_int_t start, ngx_int_t stop);
ngx_int_t cfml_redis_llen(cfml_redis_conn_t *conn, ngx_str_t *key);

/*
 * Set Commands
 */

ngx_int_t cfml_redis_sadd(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *member);
ngx_int_t cfml_redis_srem(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *member);
ngx_int_t cfml_redis_sismember(cfml_redis_conn_t *conn, ngx_str_t *key,
    ngx_str_t *member);
ngx_array_t *cfml_redis_smembers(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key);
ngx_int_t cfml_redis_scard(cfml_redis_conn_t *conn, ngx_str_t *key);

/*
 * Pub/Sub (basic support)
 */

ngx_int_t cfml_redis_publish(cfml_redis_conn_t *conn, ngx_str_t *channel,
    ngx_str_t *message);

/*
 * Transaction Commands
 */

ngx_int_t cfml_redis_multi(cfml_redis_conn_t *conn);
cfml_redis_reply_t *cfml_redis_exec(cfml_redis_conn_t *conn, ngx_pool_t *pool);
ngx_int_t cfml_redis_discard(cfml_redis_conn_t *conn);

/*
 * Session Storage (using Redis)
 */

ngx_int_t cfml_redis_session_init(cfml_context_t *ctx);
ngx_int_t cfml_redis_session_load(cfml_context_t *ctx, ngx_str_t *session_id);
ngx_int_t cfml_redis_session_save(cfml_context_t *ctx);
ngx_int_t cfml_redis_session_destroy(cfml_context_t *ctx, ngx_str_t *session_id);

/*
 * CFML Value Serialization for Redis
 */

ngx_str_t *cfml_redis_serialize_value(ngx_pool_t *pool, cfml_value_t *value);
cfml_value_t *cfml_redis_deserialize_value(ngx_pool_t *pool, ngx_str_t *data);

/*
 * CFML Function Implementations
 */

/* RedisConnect(host, port [, password] [, db]) */
cfml_value_t *cfml_func_redisconnect(cfml_context_t *ctx, ngx_array_t *args);

/* RedisGet(key) */
cfml_value_t *cfml_func_redisget(cfml_context_t *ctx, ngx_array_t *args);

/* RedisSet(key, value [, ttl]) */
cfml_value_t *cfml_func_redisset(cfml_context_t *ctx, ngx_array_t *args);

/* RedisDel(key) */
cfml_value_t *cfml_func_redisdel(cfml_context_t *ctx, ngx_array_t *args);

/* RedisExists(key) */
cfml_value_t *cfml_func_redisexists(cfml_context_t *ctx, ngx_array_t *args);

/* RedisExpire(key, seconds) */
cfml_value_t *cfml_func_redisexpire(cfml_context_t *ctx, ngx_array_t *args);

/* RedisCommand(command, args...) */
cfml_value_t *cfml_func_rediscommand(cfml_context_t *ctx, ngx_array_t *args);

/* RedisHSet(key, field, value) */
cfml_value_t *cfml_func_redishset(cfml_context_t *ctx, ngx_array_t *args);

/* RedisHGet(key, field) */
cfml_value_t *cfml_func_redishget(cfml_context_t *ctx, ngx_array_t *args);

/* RedisHGetAll(key) */
cfml_value_t *cfml_func_redishgetall(cfml_context_t *ctx, ngx_array_t *args);

/* CacheGet(key) - Higher level caching API */
cfml_value_t *cfml_func_cacheget(cfml_context_t *ctx, ngx_array_t *args);

/* CachePut(key, value [, ttl]) */
cfml_value_t *cfml_func_cacheput(cfml_context_t *ctx, ngx_array_t *args);

/* CacheRemove(key) */
cfml_value_t *cfml_func_cacheremove(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_REDIS_H_ */
