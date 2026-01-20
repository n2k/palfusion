/*
 * CFML Redis/Valkey - Native Redis client implementation
 * RESP protocol parser with connection pooling
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "cfml_redis.h"
#include "cfml_json.h"
#include "cfml_variables.h"

#define REDIS_DEFAULT_PORT      6379
#define REDIS_DEFAULT_TIMEOUT   5000
#define REDIS_RECV_BUF_SIZE     8192
#define REDIS_MAX_INLINE        65536

/* Global default connection */
static cfml_redis_conn_t *cfml_redis_default_conn = NULL;
/* TODO: Implement connection pooling
static cfml_redis_pool_t *cfml_redis_default_pool = NULL;
*/

/* Forward declarations */
static cfml_redis_reply_t *parse_redis_reply(cfml_redis_conn_t *conn, 
    ngx_pool_t *pool);
static ngx_int_t send_redis_command(cfml_redis_conn_t *conn, 
    ngx_uint_t argc, ngx_str_t *argv);

ngx_int_t
cfml_redis_init(ngx_cycle_t *cycle)
{
    /* Initialize default pool if configured */
    /* For now, just mark as initialized */
    return NGX_OK;
}

void
cfml_redis_cleanup(ngx_cycle_t *cycle)
{
    if (cfml_redis_default_conn) {
        cfml_redis_close(cfml_redis_default_conn);
        cfml_redis_default_conn = NULL;
    }
}

/* Create new connection */
cfml_redis_conn_t *
cfml_redis_connect(ngx_pool_t *pool, ngx_str_t *host, ngx_uint_t port,
    ngx_msec_t timeout)
{
    cfml_redis_conn_t *conn;
    struct addrinfo hints, *result;
    char port_str[8];
    int sock;
    struct timeval tv;
    
    conn = ngx_pcalloc(pool, sizeof(cfml_redis_conn_t));
    if (conn == NULL) {
        return NULL;
    }
    
    conn->pool = pool;
    conn->host = *host;
    conn->port = port ? port : REDIS_DEFAULT_PORT;
    conn->timeout = timeout ? timeout : REDIS_DEFAULT_TIMEOUT;
    conn->socket = -1;
    conn->state = CFML_REDIS_DISCONNECTED;
    
    /* Allocate receive buffer */
    conn->recv_buf_size = REDIS_RECV_BUF_SIZE;
    conn->recv_buf = ngx_pnalloc(pool, conn->recv_buf_size);
    if (conn->recv_buf == NULL) {
        return NULL;
    }
    conn->recv_buf_pos = 0;
    
    /* Resolve host */
    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    /* Ensure null-terminated host */
    u_char *host_str = ngx_pnalloc(pool, host->len + 1);
    ngx_memcpy(host_str, host->data, host->len);
    host_str[host->len] = '\0';
    
    ngx_snprintf((u_char *)port_str, sizeof(port_str), "%d%Z", (int)conn->port);
    
    if (getaddrinfo((char *)host_str, port_str, &hints, &result) != 0) {
        return NULL;
    }
    
    /* Create socket */
    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(result);
        return NULL;
    }
    
    /* Set timeout */
    tv.tv_sec = conn->timeout / 1000;
    tv.tv_usec = (conn->timeout % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    /* Connect */
    if (connect(sock, result->ai_addr, result->ai_addrlen) < 0) {
        freeaddrinfo(result);
        close(sock);
        return NULL;
    }
    
    freeaddrinfo(result);
    
    conn->socket = sock;
    conn->state = CFML_REDIS_CONNECTED;
    
    return conn;
}

/* Close connection */
void
cfml_redis_close(cfml_redis_conn_t *conn)
{
    if (conn == NULL) {
        return;
    }
    
    if (conn->socket >= 0) {
        close(conn->socket);
        conn->socket = -1;
    }
    
    conn->state = CFML_REDIS_DISCONNECTED;
}

/* Authenticate */
ngx_int_t
cfml_redis_auth(cfml_redis_conn_t *conn, ngx_str_t *password, ngx_str_t *username)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    ngx_uint_t argc = 2;
    
    ngx_str_set(&argv[0], "AUTH");
    
    if (username && username->len > 0) {
        argv[1] = *username;
        argv[2] = *password;
        argc = 3;
    } else {
        argv[1] = *password;
    }
    
    if (send_redis_command(conn, argc, argv) != NGX_OK) {
        return NGX_ERROR;
    }
    
    reply = parse_redis_reply(conn, conn->pool);
    if (reply == NULL || reply->type == CFML_REDIS_ERROR) {
        return NGX_ERROR;
    }
    
    conn->state = CFML_REDIS_AUTHENTICATED;
    return NGX_OK;
}

/* Select database */
ngx_int_t
cfml_redis_select(cfml_redis_conn_t *conn, ngx_int_t db)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    u_char db_str[16];
    
    ngx_str_set(&argv[0], "SELECT");
    argv[1].data = db_str;
    argv[1].len = ngx_sprintf(db_str, "%d", (int)db) - db_str;
    
    if (send_redis_command(conn, 2, argv) != NGX_OK) {
        return NGX_ERROR;
    }
    
    reply = parse_redis_reply(conn, conn->pool);
    if (reply == NULL || reply->type == CFML_REDIS_ERROR) {
        return NGX_ERROR;
    }
    
    conn->db = db;
    return NGX_OK;
}

/* Ping */
ngx_int_t
cfml_redis_ping(cfml_redis_conn_t *conn)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[1];
    
    ngx_str_set(&argv[0], "PING");
    
    if (send_redis_command(conn, 1, argv) != NGX_OK) {
        return NGX_ERROR;
    }
    
    reply = parse_redis_reply(conn, conn->pool);
    if (reply == NULL || reply->type == CFML_REDIS_ERROR) {
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

/* Send RESP command */
static ngx_int_t
send_redis_command(cfml_redis_conn_t *conn, ngx_uint_t argc, ngx_str_t *argv)
{
    u_char buf[REDIS_MAX_INLINE];
    u_char *p;
    ngx_uint_t i;
    ssize_t sent;
    
    if (conn->socket < 0) {
        return NGX_ERROR;
    }
    
    p = buf;
    
    /* RESP array format: *<argc>\r\n */
    p = ngx_sprintf(p, "*%d\r\n", (int)argc);
    
    /* Each argument: $<len>\r\n<data>\r\n */
    for (i = 0; i < argc; i++) {
        p = ngx_sprintf(p, "$%d\r\n", (int)argv[i].len);
        if (p + argv[i].len + 2 > buf + sizeof(buf)) {
            return NGX_ERROR;  /* Command too long */
        }
        p = ngx_copy(p, argv[i].data, argv[i].len);
        *p++ = '\r';
        *p++ = '\n';
    }
    
    /* Send */
    sent = send(conn->socket, buf, p - buf, 0);
    if (sent != (ssize_t)(p - buf)) {
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

/* Read line from socket into buffer */
static ngx_int_t
read_redis_line(cfml_redis_conn_t *conn, u_char **line, size_t *len)
{
    u_char *p, *end;
    ssize_t n;
    
    while (1) {
        /* Check if we have a complete line */
        p = conn->recv_buf;
        end = conn->recv_buf + conn->recv_buf_pos;
        
        while (p < end - 1) {
            if (*p == '\r' && *(p + 1) == '\n') {
                *line = conn->recv_buf;
                *len = p - conn->recv_buf;
                
                /* Move remaining data to start */
                size_t remaining = end - p - 2;
                if (remaining > 0) {
                    ngx_memmove(conn->recv_buf, p + 2, remaining);
                }
                conn->recv_buf_pos = remaining;
                
                return NGX_OK;
            }
            p++;
        }
        
        /* Need more data */
        if (conn->recv_buf_pos >= conn->recv_buf_size - 1) {
            return NGX_ERROR;  /* Buffer full */
        }
        
        n = recv(conn->socket, conn->recv_buf + conn->recv_buf_pos,
                 conn->recv_buf_size - conn->recv_buf_pos - 1, 0);
        if (n <= 0) {
            return NGX_ERROR;
        }
        
        conn->recv_buf_pos += n;
    }
}

/* Read exact number of bytes */
static ngx_int_t
read_redis_bytes(cfml_redis_conn_t *conn, u_char *dst, size_t count)
{
    ssize_t n;
    
    /* First use buffered data */
    if (conn->recv_buf_pos > 0) {
        size_t available = conn->recv_buf_pos;
        size_t to_copy = available < count ? available : count;
        
        ngx_memcpy(dst, conn->recv_buf, to_copy);
        
        if (to_copy < available) {
            ngx_memmove(conn->recv_buf, conn->recv_buf + to_copy, 
                       available - to_copy);
        }
        conn->recv_buf_pos -= to_copy;
        
        dst += to_copy;
        count -= to_copy;
    }
    
    /* Read remaining from socket */
    while (count > 0) {
        n = recv(conn->socket, dst, count, 0);
        if (n <= 0) {
            return NGX_ERROR;
        }
        dst += n;
        count -= n;
    }
    
    return NGX_OK;
}

/* Parse RESP reply */
static cfml_redis_reply_t *
parse_redis_reply(cfml_redis_conn_t *conn, ngx_pool_t *pool)
{
    cfml_redis_reply_t *reply;
    u_char *line;
    size_t len;
    int64_t count;
    ngx_uint_t i;
    
    reply = ngx_pcalloc(pool, sizeof(cfml_redis_reply_t));
    if (reply == NULL) {
        return NULL;
    }
    reply->pool = pool;
    
    if (read_redis_line(conn, &line, &len) != NGX_OK) {
        return NULL;
    }
    
    if (len == 0) {
        return NULL;
    }
    
    reply->type = line[0];
    line++;
    len--;
    
    switch (reply->type) {
    case CFML_REDIS_STRING:
    case CFML_REDIS_ERROR:
        /* Simple string or error */
        reply->str.data = ngx_pnalloc(pool, len + 1);
        if (reply->str.data == NULL) {
            return NULL;
        }
        ngx_memcpy(reply->str.data, line, len);
        reply->str.data[len] = '\0';
        reply->str.len = len;
        break;
        
    case CFML_REDIS_INTEGER:
        /* Integer */
        reply->integer = ngx_atoi(line, len);
        break;
        
    case CFML_REDIS_BULK:
        /* Bulk string */
        count = ngx_atoi(line, len);
        if (count < 0) {
            reply->type = CFML_REDIS_NULL;
            break;
        }
        
        reply->str.len = count;
        reply->str.data = ngx_pnalloc(pool, count + 1);
        if (reply->str.data == NULL) {
            return NULL;
        }
        
        if (read_redis_bytes(conn, reply->str.data, count) != NGX_OK) {
            return NULL;
        }
        reply->str.data[count] = '\0';
        
        /* Skip trailing \r\n */
        u_char crlf[2];
        read_redis_bytes(conn, crlf, 2);
        break;
        
    case CFML_REDIS_ARRAY:
        /* Array */
        count = ngx_atoi(line, len);
        if (count < 0) {
            reply->type = CFML_REDIS_NULL;
            break;
        }
        
        reply->elements = ngx_array_create(pool, count, 
                                           sizeof(cfml_redis_reply_t *));
        if (reply->elements == NULL) {
            return NULL;
        }
        
        for (i = 0; i < (ngx_uint_t)count; i++) {
            cfml_redis_reply_t **elem = ngx_array_push(reply->elements);
            if (elem == NULL) {
                return NULL;
            }
            *elem = parse_redis_reply(conn, pool);
            if (*elem == NULL) {
                return NULL;
            }
        }
        break;
        
    default:
        /* Unknown type */
        return NULL;
    }
    
    return reply;
}

/* Execute command with array */
cfml_redis_reply_t *
cfml_redis_command_argv(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_uint_t argc, ngx_str_t *argv)
{
    if (send_redis_command(conn, argc, argv) != NGX_OK) {
        return NULL;
    }
    
    return parse_redis_reply(conn, pool);
}

/*
 * String Commands Implementation
 */

ngx_int_t
cfml_redis_set(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *value,
    ngx_int_t ttl)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[5];
    ngx_uint_t argc = 3;
    u_char ttl_str[16];
    
    ngx_str_set(&argv[0], "SET");
    argv[1] = *key;
    argv[2] = *value;
    
    if (ttl > 0) {
        ngx_str_set(&argv[3], "EX");
        argv[4].data = ttl_str;
        argv[4].len = ngx_sprintf(ttl_str, "%d", (int)ttl) - ttl_str;
        argc = 5;
    }
    
    reply = cfml_redis_command_argv(conn, conn->pool, argc, argv);
    
    return (reply && reply->type != CFML_REDIS_ERROR) ? NGX_OK : NGX_ERROR;
}

ngx_str_t *
cfml_redis_get(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    ngx_str_t *result;
    
    ngx_str_set(&argv[0], "GET");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, pool, 2, argv);
    
    if (reply == NULL || reply->type == CFML_REDIS_NULL || 
        reply->type == CFML_REDIS_ERROR) {
        return NULL;
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    *result = reply->str;
    return result;
}

ngx_int_t
cfml_redis_del(cfml_redis_conn_t *conn, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "DEL");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_exists(cfml_redis_conn_t *conn, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "EXISTS");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_expire(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_int_t seconds)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    u_char sec_str[16];
    
    ngx_str_set(&argv[0], "EXPIRE");
    argv[1] = *key;
    argv[2].data = sec_str;
    argv[2].len = ngx_sprintf(sec_str, "%d", (int)seconds) - sec_str;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_ttl(cfml_redis_conn_t *conn, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "TTL");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : -2;
}

ngx_int_t
cfml_redis_incr(cfml_redis_conn_t *conn, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "INCR");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_decr(cfml_redis_conn_t *conn, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "DECR");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

/*
 * Hash Commands Implementation
 */

ngx_int_t
cfml_redis_hset(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *field,
    ngx_str_t *value)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[4];
    
    ngx_str_set(&argv[0], "HSET");
    argv[1] = *key;
    argv[2] = *field;
    argv[3] = *value;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 4, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? NGX_OK : NGX_ERROR;
}

ngx_str_t *
cfml_redis_hget(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key,
    ngx_str_t *field)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    ngx_str_t *result;
    
    ngx_str_set(&argv[0], "HGET");
    argv[1] = *key;
    argv[2] = *field;
    
    reply = cfml_redis_command_argv(conn, pool, 3, argv);
    
    if (reply == NULL || reply->type == CFML_REDIS_NULL) {
        return NULL;
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    *result = reply->str;
    return result;
}

cfml_struct_t *
cfml_redis_hgetall(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key)
{
    cfml_redis_reply_t *reply;
    cfml_redis_reply_t **elements;
    cfml_struct_t *result;
    ngx_str_t argv[2];
    ngx_uint_t i;
    
    ngx_str_set(&argv[0], "HGETALL");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, pool, 2, argv);
    
    if (reply == NULL || reply->type != CFML_REDIS_ARRAY) {
        return NULL;
    }
    
    result = cfml_struct_new(pool);
    if (result == NULL) {
        return NULL;
    }
    
    elements = reply->elements->elts;
    for (i = 0; i + 1 < reply->elements->nelts; i += 2) {
        cfml_struct_set(result, &elements[i]->str,
                        cfml_create_string(pool, &elements[i + 1]->str));
    }
    
    return result;
}

/*
 * List Commands
 */

ngx_int_t
cfml_redis_lpush(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *value)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "LPUSH");
    argv[1] = *key;
    argv[2] = *value;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_rpush(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *value)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "RPUSH");
    argv[1] = *key;
    argv[2] = *value;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t
cfml_redis_publish(cfml_redis_conn_t *conn, ngx_str_t *channel, ngx_str_t *message)
{
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "PUBLISH");
    argv[1] = *channel;
    argv[2] = *message;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

/*
 * Value serialization for Redis storage
 */

ngx_str_t *
cfml_redis_serialize_value(ngx_pool_t *pool, cfml_value_t *value)
{
    /* Use JSON for serialization */
    return cfml_json_serialize(pool, value);
}

cfml_value_t *
cfml_redis_deserialize_value(ngx_pool_t *pool, ngx_str_t *data)
{
    return cfml_json_parse(pool, data);
}

/*
 * CFML Function Implementations
 */

cfml_value_t *
cfml_func_redisconnect(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t host;
    ngx_uint_t port = REDIS_DEFAULT_PORT;
    ngx_str_t password = ngx_null_string;
    ngx_int_t db = 0;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    host = argv[0]->data.string;
    
    if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_INTEGER) {
        port = argv[1]->data.integer;
    }
    
    if (args->nelts >= 3 && argv[2]->type == CFML_TYPE_STRING) {
        password = argv[2]->data.string;
    }
    
    if (args->nelts >= 4 && argv[3]->type == CFML_TYPE_INTEGER) {
        db = argv[3]->data.integer;
    }
    
    /* Close existing connection */
    if (cfml_redis_default_conn) {
        cfml_redis_close(cfml_redis_default_conn);
    }
    
    /* Connect */
    cfml_redis_default_conn = cfml_redis_connect(ctx->pool, &host, port,
        REDIS_DEFAULT_TIMEOUT);
    
    if (cfml_redis_default_conn == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Authenticate if password provided */
    if (password.len > 0) {
        if (cfml_redis_auth(cfml_redis_default_conn, &password, NULL) != NGX_OK) {
            cfml_redis_close(cfml_redis_default_conn);
            cfml_redis_default_conn = NULL;
            return cfml_create_boolean(ctx->pool, 0);
        }
    }
    
    /* Select database */
    if (db > 0) {
        cfml_redis_select(cfml_redis_default_conn, db);
    }
    
    return cfml_create_boolean(ctx->pool, 1);
}

cfml_value_t *
cfml_func_redisget(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *result;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    result = cfml_redis_get(cfml_redis_default_conn, ctx->pool, 
                           &argv[0]->data.string);
    
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    return cfml_create_string(ctx->pool, result);
}

cfml_value_t *
cfml_func_redisset(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t value_str;
    ngx_int_t ttl = 0;
    ngx_int_t result;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 2) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Convert value to string */
    if (argv[1]->type == CFML_TYPE_STRING) {
        value_str = argv[1]->data.string;
    } else {
        /* Serialize complex types as JSON */
        ngx_str_t *json = cfml_redis_serialize_value(ctx->pool, argv[1]);
        if (json == NULL) {
            return cfml_create_boolean(ctx->pool, 0);
        }
        value_str = *json;
    }
    
    if (args->nelts >= 3 && argv[2]->type == CFML_TYPE_INTEGER) {
        ttl = argv[2]->data.integer;
    }
    
    result = cfml_redis_set(cfml_redis_default_conn, &argv[0]->data.string,
                           &value_str, ttl);
    
    return cfml_create_boolean(ctx->pool, result == NGX_OK);
}

cfml_value_t *
cfml_func_redisdel(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    return cfml_create_integer(ctx->pool, 
        cfml_redis_del(cfml_redis_default_conn, &argv[0]->data.string));
}

cfml_value_t *
cfml_func_redisexists(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    return cfml_create_boolean(ctx->pool, 
        cfml_redis_exists(cfml_redis_default_conn, &argv[0]->data.string) > 0);
}

cfml_value_t *
cfml_func_redisexpire(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 2) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING || argv[1]->type != CFML_TYPE_INTEGER) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    return cfml_create_boolean(ctx->pool,
        cfml_redis_expire(cfml_redis_default_conn, &argv[0]->data.string,
                         argv[1]->data.integer) > 0);
}

cfml_value_t *
cfml_func_redishset(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t value_str;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 3) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING || argv[1]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    /* Convert value to string */
    if (argv[2]->type == CFML_TYPE_STRING) {
        value_str = argv[2]->data.string;
    } else {
        ngx_str_t *json = cfml_redis_serialize_value(ctx->pool, argv[2]);
        if (json == NULL) {
            return cfml_create_boolean(ctx->pool, 0);
        }
        value_str = *json;
    }
    
    return cfml_create_boolean(ctx->pool,
        cfml_redis_hset(cfml_redis_default_conn, &argv[0]->data.string,
                       &argv[1]->data.string, &value_str) == NGX_OK);
}

cfml_value_t *
cfml_func_redishget(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *result;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 2) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING || argv[1]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    result = cfml_redis_hget(cfml_redis_default_conn, ctx->pool,
                            &argv[0]->data.string, &argv[1]->data.string);
    
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    return cfml_create_string(ctx->pool, result);
}

cfml_value_t *
cfml_func_redishgetall(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_struct_t *result;
    cfml_value_t *val;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_struct(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_struct(ctx->pool);
    }
    
    result = cfml_redis_hgetall(cfml_redis_default_conn, ctx->pool,
                               &argv[0]->data.string);
    
    if (result == NULL) {
        return cfml_create_struct(ctx->pool);
    }
    
    val = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    val->type = CFML_TYPE_STRUCT;
    val->data.structure = result;
    return val;
}

/* Generic command executor */
cfml_value_t *
cfml_func_rediscommand(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_redis_reply_t *reply;
    ngx_str_t *cmd_argv;
    ngx_uint_t i;
    
    if (cfml_redis_default_conn == NULL || args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    /* Build command arguments */
    cmd_argv = ngx_pnalloc(ctx->pool, args->nelts * sizeof(ngx_str_t));
    if (cmd_argv == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    for (i = 0; i < args->nelts; i++) {
        if (argv[i]->type == CFML_TYPE_STRING) {
            cmd_argv[i] = argv[i]->data.string;
        } else {
            ngx_str_t *str = cfml_redis_serialize_value(ctx->pool, argv[i]);
            if (str) {
                cmd_argv[i] = *str;
            } else {
                ngx_str_set(&cmd_argv[i], "");
            }
        }
    }
    
    reply = cfml_redis_command_argv(cfml_redis_default_conn, ctx->pool,
                                    args->nelts, cmd_argv);
    
    if (reply == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* Convert reply to CFML value */
    switch (reply->type) {
    case CFML_REDIS_STRING:
    case CFML_REDIS_BULK:
        return cfml_create_string(ctx->pool, &reply->str);
        
    case CFML_REDIS_INTEGER:
        return cfml_create_integer(ctx->pool, reply->integer);
        
    case CFML_REDIS_ARRAY:
        {
            cfml_value_t *arr = cfml_create_array(ctx->pool);
            cfml_redis_reply_t **elements = reply->elements->elts;
            for (i = 0; i < reply->elements->nelts; i++) {
                if (elements[i]->type == CFML_REDIS_BULK ||
                    elements[i]->type == CFML_REDIS_STRING) {
                    cfml_array_append(arr->data.array,
                        cfml_create_string(ctx->pool, &elements[i]->str));
                } else if (elements[i]->type == CFML_REDIS_INTEGER) {
                    cfml_array_append(arr->data.array,
                        cfml_create_integer(ctx->pool, elements[i]->integer));
                }
            }
            return arr;
        }
        
    case CFML_REDIS_ERROR:
        return cfml_create_string(ctx->pool, &reply->str);
        
    default:
        return cfml_create_null(ctx->pool);
    }
}

/* Cache API - higher level wrappers */
cfml_value_t *
cfml_func_cacheget(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *result = cfml_func_redisget(ctx, args);
    
    /* Try to deserialize as JSON if it looks like it */
    if (result && result->type == CFML_TYPE_STRING &&
        result->data.string.len > 0 &&
        (result->data.string.data[0] == '{' || result->data.string.data[0] == '[')) {
        cfml_value_t *parsed = cfml_redis_deserialize_value(ctx->pool, 
            &result->data.string);
        if (parsed) {
            return parsed;
        }
    }
    
    return result;
}

cfml_value_t *
cfml_func_cacheput(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_func_redisset(ctx, args);
}

cfml_value_t *
cfml_func_cacheremove(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_func_redisdel(ctx, args);
    return cfml_create_boolean(ctx->pool, 1);
}

/* Stub implementations for pool functions */
cfml_redis_pool_t *
cfml_redis_pool_create(ngx_pool_t *pool, ngx_str_t *host,
    ngx_uint_t port, ngx_str_t *password, ngx_int_t db)
{
    (void)pool;
    (void)host;
    (void)port;
    (void)password;
    (void)db;
    return NULL;
}

cfml_redis_conn_t *
cfml_redis_get_connection(cfml_redis_pool_t *pool)
{
    (void)pool;
    return cfml_redis_default_conn;
}

void
cfml_redis_release_connection(cfml_redis_pool_t *pool, cfml_redis_conn_t *conn)
{
    (void)pool;
    (void)conn;
}

void
cfml_redis_free_reply(cfml_redis_reply_t *reply)
{
    (void)reply;
    /* Pool-allocated, freed with pool */
}

/* Session storage stubs */
ngx_int_t cfml_redis_session_init(cfml_context_t *ctx) { (void)ctx; return NGX_OK; }
ngx_int_t cfml_redis_session_load(cfml_context_t *ctx, ngx_str_t *session_id) { 
    (void)ctx; (void)session_id; return NGX_OK; 
}
ngx_int_t cfml_redis_session_save(cfml_context_t *ctx) { (void)ctx; return NGX_OK; }
ngx_int_t cfml_redis_session_destroy(cfml_context_t *ctx, ngx_str_t *session_id) {
    (void)ctx; (void)session_id; return NGX_OK;
}

/* Remaining command stubs */
ngx_int_t cfml_redis_incrby(cfml_redis_conn_t *conn, ngx_str_t *key, int64_t amount) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    u_char amt_str[32];
    
    ngx_str_set(&argv[0], "INCRBY");
    argv[1] = *key;
    argv[2].data = amt_str;
    argv[2].len = ngx_sprintf(amt_str, "%L", amount) - amt_str;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_hdel(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *field) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "HDEL");
    argv[1] = *key;
    argv[2] = *field;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_hexists(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *field) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "HEXISTS");
    argv[1] = *key;
    argv[2] = *field;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_str_t *cfml_redis_lpop(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    ngx_str_t *result;
    
    ngx_str_set(&argv[0], "LPOP");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, pool, 2, argv);
    if (reply == NULL || reply->type == CFML_REDIS_NULL) return NULL;
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    *result = reply->str;
    return result;
}

ngx_str_t *cfml_redis_rpop(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    ngx_str_t *result;
    
    ngx_str_set(&argv[0], "RPOP");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, pool, 2, argv);
    if (reply == NULL || reply->type == CFML_REDIS_NULL) return NULL;
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    *result = reply->str;
    return result;
}

ngx_array_t *cfml_redis_lrange(cfml_redis_conn_t *conn, ngx_pool_t *pool,
    ngx_str_t *key, ngx_int_t start, ngx_int_t stop) {
    (void)conn; (void)pool; (void)key; (void)start; (void)stop;
    return NULL;
}

ngx_int_t cfml_redis_llen(cfml_redis_conn_t *conn, ngx_str_t *key) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "LLEN");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_sadd(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *member) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "SADD");
    argv[1] = *key;
    argv[2] = *member;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_srem(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *member) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "SREM");
    argv[1] = *key;
    argv[2] = *member;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_sismember(cfml_redis_conn_t *conn, ngx_str_t *key, ngx_str_t *member) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[3];
    
    ngx_str_set(&argv[0], "SISMEMBER");
    argv[1] = *key;
    argv[2] = *member;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 3, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_array_t *cfml_redis_smembers(cfml_redis_conn_t *conn, ngx_pool_t *pool, ngx_str_t *key) {
    (void)conn; (void)pool; (void)key;
    return NULL;
}

ngx_int_t cfml_redis_scard(cfml_redis_conn_t *conn, ngx_str_t *key) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[2];
    
    ngx_str_set(&argv[0], "SCARD");
    argv[1] = *key;
    
    reply = cfml_redis_command_argv(conn, conn->pool, 2, argv);
    return (reply && reply->type == CFML_REDIS_INTEGER) ? reply->integer : 0;
}

ngx_int_t cfml_redis_multi(cfml_redis_conn_t *conn) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[1];
    ngx_str_set(&argv[0], "MULTI");
    reply = cfml_redis_command_argv(conn, conn->pool, 1, argv);
    return (reply && reply->type == CFML_REDIS_STRING) ? NGX_OK : NGX_ERROR;
}

cfml_redis_reply_t *cfml_redis_exec(cfml_redis_conn_t *conn, ngx_pool_t *pool) {
    ngx_str_t argv[1];
    ngx_str_set(&argv[0], "EXEC");
    return cfml_redis_command_argv(conn, pool, 1, argv);
}

ngx_int_t cfml_redis_discard(cfml_redis_conn_t *conn) {
    cfml_redis_reply_t *reply;
    ngx_str_t argv[1];
    ngx_str_set(&argv[0], "DISCARD");
    reply = cfml_redis_command_argv(conn, conn->pool, 1, argv);
    return (reply && reply->type == CFML_REDIS_STRING) ? NGX_OK : NGX_ERROR;
}
