/*
 * CFML Database - MySQL, PostgreSQL, and SQLite native connectivity
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_database.h"
#include "cfml_variables.h"

#ifdef HAVE_MYSQL
#include <mysql/mysql.h>
#endif

#ifdef HAVE_PGSQL
#include <libpq-fe.h>
#endif

#ifdef HAVE_SQLITE
#include <sqlite3.h>
#endif

/* Global database pools */
static ngx_array_t *cfml_db_pools = NULL;
static ngx_pool_t *cfml_db_global_pool = NULL;

ngx_int_t
cfml_database_init(ngx_cycle_t *cycle)
{
    cfml_db_global_pool = cycle->pool;
    
    cfml_db_pools = ngx_array_create(cycle->pool, 4, sizeof(cfml_db_pool_t *));
    if (cfml_db_pools == NULL) {
        return NGX_ERROR;
    }
    
#ifdef HAVE_MYSQL
    if (cfml_mysql_init() != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "cfml: MySQL initialization failed");
    }
#endif

#ifdef HAVE_PGSQL
    if (cfml_pgsql_init() != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "cfml: PostgreSQL initialization failed");
    }
#endif

#ifdef HAVE_SQLITE
    if (cfml_sqlite_init() != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "cfml: SQLite initialization failed");
    }
#endif
    
    return NGX_OK;
}

void
cfml_database_cleanup(ngx_cycle_t *cycle)
{
    (void)cycle;
    
#ifdef HAVE_MYSQL
    cfml_mysql_cleanup();
#endif

#ifdef HAVE_PGSQL
    cfml_pgsql_cleanup();
#endif

#ifdef HAVE_SQLITE
    cfml_sqlite_cleanup();
#endif
}

cfml_db_driver_t
cfml_db_parse_driver(ngx_str_t *connection_string)
{
    if (ngx_strncasecmp(connection_string->data, (u_char *)"mysql://", 8) == 0) {
        return CFML_DB_MYSQL;
    }
    if (ngx_strncasecmp(connection_string->data, (u_char *)"postgresql://", 13) == 0 ||
        ngx_strncasecmp(connection_string->data, (u_char *)"postgres://", 11) == 0) {
        return CFML_DB_POSTGRESQL;
    }
    if (ngx_strncasecmp(connection_string->data, (u_char *)"sqlite://", 9) == 0 ||
        ngx_strncasecmp(connection_string->data, (u_char *)"sqlite3://", 10) == 0 ||
        ngx_strncasecmp(connection_string->data, (u_char *)"file:", 5) == 0) {
        return CFML_DB_SQLITE;
    }
    /* Also check for .db or .sqlite file extension */
    if (connection_string->len > 3) {
        u_char *ext = connection_string->data + connection_string->len - 3;
        if (ngx_strncasecmp(ext, (u_char *)".db", 3) == 0) {
            return CFML_DB_SQLITE;
        }
        if (connection_string->len > 7) {
            ext = connection_string->data + connection_string->len - 7;
            if (ngx_strncasecmp(ext, (u_char *)".sqlite", 7) == 0) {
                return CFML_DB_SQLITE;
            }
        }
    }
    return CFML_DB_UNKNOWN;
}

ngx_int_t
cfml_db_parse_connection_string(ngx_pool_t *pool, ngx_str_t *conn_str,
                                 cfml_db_connection_t *conn)
{
    u_char *p, *start, *end;
    
    end = conn_str->data + conn_str->len;
    p = conn_str->data;
    
    /* Parse driver */
    start = p;
    while (p < end && *p != ':') p++;
    
    if (ngx_strncasecmp(start, (u_char *)"mysql", 5) == 0) {
        conn->driver = CFML_DB_MYSQL;
        conn->port = 3306;
    } else if (ngx_strncasecmp(start, (u_char *)"postgresql", 10) == 0 ||
               ngx_strncasecmp(start, (u_char *)"postgres", 8) == 0) {
        conn->driver = CFML_DB_POSTGRESQL;
        conn->port = 5432;
    } else if (ngx_strncasecmp(start, (u_char *)"sqlite", 6) == 0 ||
               ngx_strncasecmp(start, (u_char *)"file", 4) == 0) {
        conn->driver = CFML_DB_SQLITE;
        conn->port = 0;
    } else {
        return NGX_ERROR;
    }
    
    /* Skip :// */
    if (*p == ':') p++;
    if (*p == '/') p++;
    if (*p == '/') p++;
    
    /* Parse username */
    start = p;
    while (p < end && *p != ':' && *p != '@') p++;
    conn->username.data = ngx_pnalloc(pool, p - start + 1);
    ngx_memcpy(conn->username.data, start, p - start);
    conn->username.len = p - start;
    conn->username.data[conn->username.len] = '\0';
    
    /* Parse password */
    if (*p == ':') {
        p++;
        start = p;
        while (p < end && *p != '@') p++;
        conn->password.data = ngx_pnalloc(pool, p - start + 1);
        ngx_memcpy(conn->password.data, start, p - start);
        conn->password.len = p - start;
        conn->password.data[conn->password.len] = '\0';
    }
    
    /* Skip @ */
    if (*p == '@') p++;
    
    /* Parse host */
    start = p;
    while (p < end && *p != ':' && *p != '/') p++;
    conn->host.data = ngx_pnalloc(pool, p - start + 1);
    ngx_memcpy(conn->host.data, start, p - start);
    conn->host.len = p - start;
    conn->host.data[conn->host.len] = '\0';
    
    /* Parse port */
    if (*p == ':') {
        p++;
        conn->port = ngx_atoi(p, end - p);
        while (p < end && *p != '/') p++;
    }
    
    /* Skip / */
    if (*p == '/') p++;
    
    /* Parse database */
    start = p;
    while (p < end && *p != '?') p++;
    conn->database.data = ngx_pnalloc(pool, p - start + 1);
    ngx_memcpy(conn->database.data, start, p - start);
    conn->database.len = p - start;
    conn->database.data[conn->database.len] = '\0';
    
    conn->pool = pool;
    conn->state = CFML_DB_CONN_CLOSED;
    
    return NGX_OK;
}

cfml_db_pool_t *
cfml_db_pool_create(ngx_pool_t *pool, ngx_str_t *name, ngx_str_t *connection_string)
{
    cfml_db_pool_t *db_pool;
    cfml_db_pool_t **stored;
    
    db_pool = ngx_pcalloc(pool, sizeof(cfml_db_pool_t));
    if (db_pool == NULL) {
        return NULL;
    }
    
    db_pool->name.len = name->len;
    db_pool->name.data = ngx_pnalloc(pool, name->len + 1);
    ngx_memcpy(db_pool->name.data, name->data, name->len);
    db_pool->name.data[name->len] = '\0';
    
    db_pool->connection_string.len = connection_string->len;
    db_pool->connection_string.data = ngx_pnalloc(pool, connection_string->len + 1);
    ngx_memcpy(db_pool->connection_string.data, connection_string->data, connection_string->len);
    db_pool->connection_string.data[connection_string->len] = '\0';
    
    db_pool->driver = cfml_db_parse_driver(connection_string);
    db_pool->min_connections = 1;
    db_pool->max_connections = 10;
    db_pool->idle_timeout = 300000;  /* 5 minutes */
    db_pool->pool = pool;
    
    ngx_queue_init(&db_pool->free_connections);
    ngx_queue_init(&db_pool->used_connections);
    
    /* Store in global pools array */
    if (cfml_db_pools != NULL) {
        stored = ngx_array_push(cfml_db_pools);
        if (stored != NULL) {
            *stored = db_pool;
        }
    }
    
    return db_pool;
}

static cfml_db_pool_t *
cfml_db_find_pool(ngx_str_t *name)
{
    cfml_db_pool_t **pools;
    ngx_uint_t i;
    
    if (cfml_db_pools == NULL) {
        return NULL;
    }
    
    pools = cfml_db_pools->elts;
    for (i = 0; i < cfml_db_pools->nelts; i++) {
        if (pools[i]->name.len == name->len &&
            ngx_strncasecmp(pools[i]->name.data, name->data, name->len) == 0) {
            return pools[i];
        }
    }
    
    return NULL;
}

cfml_db_connection_t *
cfml_db_get_connection(cfml_context_t *ctx, ngx_str_t *datasource)
{
    cfml_db_pool_t *pool;
    cfml_db_connection_t *conn;
    ngx_queue_t *q;
    
    pool = cfml_db_find_pool(datasource);
    if (pool == NULL) {
        return NULL;
    }
    
    /* Try to get from free pool */
    if (!ngx_queue_empty(&pool->free_connections)) {
        q = ngx_queue_head(&pool->free_connections);
        conn = ngx_queue_data(q, cfml_db_connection_t, queue);
        ngx_queue_remove(q);
        
        /* Check if connection is still alive */
        if (cfml_db_ping_connection(conn) == NGX_OK) {
            conn->in_use = 1;
            conn->last_used = ngx_current_msec;
            ngx_queue_insert_tail(&pool->used_connections, &conn->queue);
            return conn;
        }
        
        /* Connection dead, close and create new */
        cfml_db_close_connection(conn);
        pool->current_count--;
    }
    
    /* Create new connection if under max */
    if (pool->current_count < pool->max_connections) {
        conn = ngx_pcalloc(ctx->pool, sizeof(cfml_db_connection_t));
        if (conn == NULL) {
            return NULL;
        }
        
        if (cfml_db_parse_connection_string(ctx->pool, &pool->connection_string, conn) != NGX_OK) {
            return NULL;
        }
        
        /* Connect based on driver */
        switch (pool->driver) {
        case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
            conn = cfml_mysql_connect(ctx->pool, &conn->host, conn->port,
                                       &conn->database, &conn->username, &conn->password);
#else
            return NULL;
#endif
            break;
            
        case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
            conn = cfml_pgsql_connect(ctx->pool, &conn->host, conn->port,
                                       &conn->database, &conn->username, &conn->password);
#else
            return NULL;
#endif
            break;
            
        case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
            conn = cfml_sqlite_connect(ctx->pool, &conn->database);
#else
            return NULL;
#endif
            break;
            
        default:
            return NULL;
        }
        
        if (conn != NULL) {
            conn->in_use = 1;
            conn->last_used = ngx_current_msec;
            pool->current_count++;
            ngx_queue_insert_tail(&pool->used_connections, &conn->queue);
        }
        
        return conn;
    }
    
    return NULL;
}

ngx_int_t
cfml_db_release_connection(cfml_db_connection_t *conn)
{
    if (conn == NULL) {
        return NGX_ERROR;
    }
    
    conn->in_use = 0;
    conn->last_used = ngx_current_msec;
    
    /* Move from used to free queue */
    ngx_queue_remove(&conn->queue);
    /* Would insert into free queue of the pool */
    
    return NGX_OK;
}

ngx_int_t
cfml_db_close_connection(cfml_db_connection_t *conn)
{
    if (conn == NULL) {
        return NGX_ERROR;
    }
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        return cfml_mysql_disconnect(conn);
#endif
        break;
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        return cfml_pgsql_disconnect(conn);
#endif
        break;
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        return cfml_sqlite_disconnect(conn);
#endif
        break;
        
    default:
        break;
    }
    
    conn->state = CFML_DB_CONN_CLOSED;
    return NGX_OK;
}

ngx_int_t
cfml_db_ping_connection(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->state != CFML_DB_CONN_OPEN) {
        return NGX_ERROR;
    }
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        return cfml_mysql_ping(conn);
#endif
        break;
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        return cfml_pgsql_ping(conn);
#endif
        break;
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        return cfml_sqlite_ping(conn);
#endif
        break;
        
    default:
        break;
    }
    
    return NGX_ERROR;
}

cfml_db_result_t *
cfml_db_execute(cfml_context_t *ctx, cfml_db_connection_t *conn,
                 ngx_str_t *sql, ngx_array_t *params)
{
    cfml_db_result_t *result;
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_db_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    if (conn == NULL) {
        result->success = 0;
        ngx_str_set(&result->error, "No database connection");
        return result;
    }
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        return cfml_mysql_query(ctx, conn, sql, params);
#else
        result->success = 0;
        ngx_str_set(&result->error, "MySQL support not compiled");
        return result;
#endif
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        return cfml_pgsql_query(ctx, conn, sql, params);
#else
        result->success = 0;
        ngx_str_set(&result->error, "PostgreSQL support not compiled");
        return result;
#endif
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        return cfml_sqlite_query(ctx, conn, sql, params);
#else
        result->success = 0;
        ngx_str_set(&result->error, "SQLite support not compiled");
        return result;
#endif
        
    default:
        result->success = 0;
        ngx_str_set(&result->error, "Unknown database driver");
        return result;
    }
}

cfml_db_result_t *
cfml_db_execute_query(cfml_context_t *ctx, ngx_str_t *datasource,
                       ngx_str_t *sql, ngx_array_t *params)
{
    cfml_db_connection_t *conn;
    cfml_db_result_t *result;
    
    conn = cfml_db_get_connection(ctx, datasource);
    if (conn == NULL) {
        result = ngx_pcalloc(ctx->pool, sizeof(cfml_db_result_t));
        if (result != NULL) {
            result->success = 0;
            ngx_str_set(&result->error, "Cannot connect to datasource");
        }
        return result;
    }
    
    result = cfml_db_execute(ctx, conn, sql, params);
    
    cfml_db_release_connection(conn);
    
    return result;
}

ngx_int_t
cfml_db_begin_transaction(cfml_db_connection_t *conn)
{
    ngx_str_t sql;
    
    if (conn == NULL || conn->in_transaction) {
        return NGX_ERROR;
    }
    
    ngx_str_set(&sql, "BEGIN");
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        if (mysql_query((MYSQL *)conn->mysql_conn, "BEGIN") == 0) {
            conn->in_transaction = 1;
            return NGX_OK;
        }
#endif
        break;
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        {
            PGresult *res = PQexec((PGconn *)conn->pg_conn, "BEGIN");
            if (PQresultStatus(res) == PGRES_COMMAND_OK) {
                PQclear(res);
                conn->in_transaction = 1;
                return NGX_OK;
            }
            PQclear(res);
        }
#endif
        break;
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        {
            ngx_str_t sql = ngx_string("BEGIN TRANSACTION");
            if (cfml_sqlite_exec(conn, &sql) == NGX_OK) {
                conn->in_transaction = 1;
                return NGX_OK;
            }
        }
#endif
        break;
        
    default:
        break;
    }
    
    return NGX_ERROR;
}

ngx_int_t
cfml_db_commit(cfml_db_connection_t *conn)
{
    if (conn == NULL || !conn->in_transaction) {
        return NGX_ERROR;
    }
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        if (mysql_query((MYSQL *)conn->mysql_conn, "COMMIT") == 0) {
            conn->in_transaction = 0;
            return NGX_OK;
        }
#endif
        break;
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        {
            PGresult *res = PQexec((PGconn *)conn->pg_conn, "COMMIT");
            if (PQresultStatus(res) == PGRES_COMMAND_OK) {
                PQclear(res);
                conn->in_transaction = 0;
                return NGX_OK;
            }
            PQclear(res);
        }
#endif
        break;
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        {
            ngx_str_t sql = ngx_string("COMMIT");
            if (cfml_sqlite_exec(conn, &sql) == NGX_OK) {
                conn->in_transaction = 0;
                return NGX_OK;
            }
        }
#endif
        break;
        
    default:
        break;
    }
    
    return NGX_ERROR;
}

ngx_int_t
cfml_db_rollback(cfml_db_connection_t *conn)
{
    if (conn == NULL || !conn->in_transaction) {
        return NGX_ERROR;
    }
    
    switch (conn->driver) {
    case CFML_DB_MYSQL:
#ifdef HAVE_MYSQL
        if (mysql_query((MYSQL *)conn->mysql_conn, "ROLLBACK") == 0) {
            conn->in_transaction = 0;
            return NGX_OK;
        }
#endif
        break;
        
    case CFML_DB_POSTGRESQL:
#ifdef HAVE_PGSQL
        {
            PGresult *res = PQexec((PGconn *)conn->pg_conn, "ROLLBACK");
            if (PQresultStatus(res) == PGRES_COMMAND_OK) {
                PQclear(res);
                conn->in_transaction = 0;
                return NGX_OK;
            }
            PQclear(res);
        }
#endif
        break;
        
    case CFML_DB_SQLITE:
#ifdef HAVE_SQLITE
        {
            ngx_str_t sql = ngx_string("ROLLBACK");
            if (cfml_sqlite_exec(conn, &sql) == NGX_OK) {
                conn->in_transaction = 0;
                return NGX_OK;
            }
        }
#endif
        break;
        
    default:
        break;
    }
    
    return NGX_ERROR;
}

/* ===== MySQL Implementation ===== */

#ifdef HAVE_MYSQL

ngx_int_t
cfml_mysql_init(void)
{
    if (mysql_library_init(0, NULL, NULL)) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
cfml_mysql_cleanup(void)
{
    mysql_library_end();
}

cfml_db_connection_t *
cfml_mysql_connect(ngx_pool_t *pool, ngx_str_t *host, ngx_uint_t port,
                    ngx_str_t *database, ngx_str_t *username, ngx_str_t *password)
{
    cfml_db_connection_t *conn;
    MYSQL *mysql;
    
    conn = ngx_pcalloc(pool, sizeof(cfml_db_connection_t));
    if (conn == NULL) {
        return NULL;
    }
    
    mysql = mysql_init(NULL);
    if (mysql == NULL) {
        return NULL;
    }
    
    /* Set options */
    mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &(unsigned int){10});
    mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &(unsigned int){30});
    mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");
    
    if (!mysql_real_connect(mysql,
                            (char *)host->data,
                            (char *)username->data,
                            (char *)password->data,
                            (char *)database->data,
                            port, NULL, 0)) {
        mysql_close(mysql);
        return NULL;
    }
    
    conn->driver = CFML_DB_MYSQL;
    conn->mysql_conn = mysql;
    conn->state = CFML_DB_CONN_OPEN;
    conn->pool = pool;
    conn->host = *host;
    conn->port = port;
    conn->database = *database;
    conn->username = *username;
    conn->password = *password;
    
    return conn;
}

ngx_int_t
cfml_mysql_disconnect(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->mysql_conn == NULL) {
        return NGX_ERROR;
    }
    
    mysql_close((MYSQL *)conn->mysql_conn);
    conn->mysql_conn = NULL;
    conn->state = CFML_DB_CONN_CLOSED;
    
    return NGX_OK;
}

ngx_int_t
cfml_mysql_ping(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->mysql_conn == NULL) {
        return NGX_ERROR;
    }
    
    return mysql_ping((MYSQL *)conn->mysql_conn) == 0 ? NGX_OK : NGX_ERROR;
}

cfml_db_result_t *
cfml_mysql_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
                  ngx_str_t *sql, ngx_array_t *params)
{
    cfml_db_result_t *result;
    MYSQL *mysql;
    MYSQL_RES *res;
    MYSQL_ROW row;
    MYSQL_FIELD *fields;
    ngx_uint_t num_fields, i;
    ngx_int_t num_rows;
    u_char *sql_str;
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_db_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    mysql = (MYSQL *)conn->mysql_conn;
    
    /* Null-terminate SQL */
    sql_str = ngx_pnalloc(ctx->pool, sql->len + 1);
    ngx_memcpy(sql_str, sql->data, sql->len);
    sql_str[sql->len] = '\0';
    
    if (mysql_query(mysql, (char *)sql_str) != 0) {
        result->success = 0;
        result->error.data = (u_char *)mysql_error(mysql);
        result->error.len = ngx_strlen(result->error.data);
        return result;
    }
    
    res = mysql_store_result(mysql);
    if (res == NULL) {
        /* Non-SELECT query */
        result->success = 1;
        result->affected_rows = mysql_affected_rows(mysql);
        result->insert_id = mysql_insert_id(mysql);
        return result;
    }
    
    /* Build query result */
    result->query = cfml_query_new(ctx->pool);
    if (result->query == NULL) {
        mysql_free_result(res);
        return NULL;
    }
    
    num_fields = mysql_num_fields(res);
    fields = mysql_fetch_fields(res);
    
    /* Add columns */
    for (i = 0; i < num_fields; i++) {
        ngx_str_t col_name;
        col_name.data = (u_char *)fields[i].name;
        col_name.len = ngx_strlen(fields[i].name);
        cfml_query_add_column(result->query, &col_name, CFML_TYPE_STRING);
    }
    
    /* Add rows */
    num_rows = 0;
    while ((row = mysql_fetch_row(res)) != NULL) {
        unsigned long *lengths = mysql_fetch_lengths(res);
        cfml_query_add_row(result->query);
        
        for (i = 0; i < num_fields; i++) {
            ngx_str_t col_name, value;
            col_name.data = (u_char *)fields[i].name;
            col_name.len = ngx_strlen(fields[i].name);
            
            if (row[i] != NULL) {
                value.data = (u_char *)row[i];
                value.len = lengths[i];
            } else {
                value.data = NULL;
                value.len = 0;
            }
            
            cfml_query_set_cell(result->query, &col_name,
                                result->query->row_count,
                                cfml_create_string(ctx->pool, &value));
        }
        num_rows++;
    }
    
    mysql_free_result(res);
    
    result->success = 1;
    result->affected_rows = num_rows;
    
    return result;
}

ngx_int_t
cfml_mysql_escape_string(ngx_pool_t *pool, cfml_db_connection_t *conn,
                          ngx_str_t *input, ngx_str_t *output)
{
    MYSQL *mysql = (MYSQL *)conn->mysql_conn;
    
    output->data = ngx_pnalloc(pool, input->len * 2 + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }
    
    output->len = mysql_real_escape_string(mysql, (char *)output->data,
                                            (char *)input->data, input->len);
    
    return NGX_OK;
}

#else /* !HAVE_MYSQL */

ngx_int_t cfml_mysql_init(void) { return NGX_OK; }
void cfml_mysql_cleanup(void) { }
cfml_db_connection_t *cfml_mysql_connect(ngx_pool_t *pool, ngx_str_t *host,
    ngx_uint_t port, ngx_str_t *database, ngx_str_t *username, ngx_str_t *password)
    { return NULL; }
ngx_int_t cfml_mysql_disconnect(cfml_db_connection_t *conn) { return NGX_ERROR; }
ngx_int_t cfml_mysql_ping(cfml_db_connection_t *conn) { return NGX_ERROR; }
cfml_db_result_t *cfml_mysql_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
    ngx_str_t *sql, ngx_array_t *params) { return NULL; }
ngx_int_t cfml_mysql_escape_string(ngx_pool_t *pool, cfml_db_connection_t *conn,
    ngx_str_t *input, ngx_str_t *output) { return NGX_ERROR; }

#endif /* HAVE_MYSQL */

/* ===== PostgreSQL Implementation ===== */

#ifdef HAVE_PGSQL

ngx_int_t
cfml_pgsql_init(void)
{
    return NGX_OK;
}

void
cfml_pgsql_cleanup(void)
{
}

cfml_db_connection_t *
cfml_pgsql_connect(ngx_pool_t *pool, ngx_str_t *host, ngx_uint_t port,
                    ngx_str_t *database, ngx_str_t *username, ngx_str_t *password)
{
    cfml_db_connection_t *conn;
    PGconn *pg;
    u_char conn_str[1024];
    
    conn = ngx_pcalloc(pool, sizeof(cfml_db_connection_t));
    if (conn == NULL) {
        return NULL;
    }
    
    ngx_snprintf(conn_str, sizeof(conn_str),
                 "host=%V port=%d dbname=%V user=%V password=%V%Z",
                 host, port, database, username, password);
    
    pg = PQconnectdb((char *)conn_str);
    if (PQstatus(pg) != CONNECTION_OK) {
        PQfinish(pg);
        return NULL;
    }
    
    /* Set UTF-8 encoding */
    PQsetClientEncoding(pg, "UTF8");
    
    conn->driver = CFML_DB_POSTGRESQL;
    conn->pg_conn = pg;
    conn->state = CFML_DB_CONN_OPEN;
    conn->pool = pool;
    conn->host = *host;
    conn->port = port;
    conn->database = *database;
    conn->username = *username;
    conn->password = *password;
    
    return conn;
}

ngx_int_t
cfml_pgsql_disconnect(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->pg_conn == NULL) {
        return NGX_ERROR;
    }
    
    PQfinish((PGconn *)conn->pg_conn);
    conn->pg_conn = NULL;
    conn->state = CFML_DB_CONN_CLOSED;
    
    return NGX_OK;
}

ngx_int_t
cfml_pgsql_ping(cfml_db_connection_t *conn)
{
    PGconn *pg;
    
    if (conn == NULL || conn->pg_conn == NULL) {
        return NGX_ERROR;
    }
    
    pg = (PGconn *)conn->pg_conn;
    return PQstatus(pg) == CONNECTION_OK ? NGX_OK : NGX_ERROR;
}

cfml_db_result_t *
cfml_pgsql_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
                  ngx_str_t *sql, ngx_array_t *params)
{
    cfml_db_result_t *result;
    PGconn *pg;
    PGresult *res;
    int num_fields, num_rows;
    int i, j;
    u_char *sql_str;
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_db_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    pg = (PGconn *)conn->pg_conn;
    
    /* Null-terminate SQL */
    sql_str = ngx_pnalloc(ctx->pool, sql->len + 1);
    ngx_memcpy(sql_str, sql->data, sql->len);
    sql_str[sql->len] = '\0';
    
    res = PQexec(pg, (char *)sql_str);
    
    switch (PQresultStatus(res)) {
    case PGRES_COMMAND_OK:
        result->success = 1;
        result->affected_rows = atoi(PQcmdTuples(res));
        PQclear(res);
        return result;
        
    case PGRES_TUPLES_OK:
        break;
        
    default:
        result->success = 0;
        result->error.data = (u_char *)PQerrorMessage(pg);
        result->error.len = ngx_strlen(result->error.data);
        PQclear(res);
        return result;
    }
    
    /* Build query result */
    result->query = cfml_query_new(ctx->pool);
    if (result->query == NULL) {
        PQclear(res);
        return NULL;
    }
    
    num_fields = PQnfields(res);
    num_rows = PQntuples(res);
    
    /* Add columns */
    for (i = 0; i < num_fields; i++) {
        ngx_str_t col_name;
        col_name.data = (u_char *)PQfname(res, i);
        col_name.len = ngx_strlen(col_name.data);
        cfml_query_add_column(result->query, &col_name, CFML_TYPE_STRING);
    }
    
    /* Add rows */
    for (j = 0; j < num_rows; j++) {
        cfml_query_add_row(result->query);
        
        for (i = 0; i < num_fields; i++) {
            ngx_str_t col_name, value;
            col_name.data = (u_char *)PQfname(res, i);
            col_name.len = ngx_strlen(col_name.data);
            
            if (!PQgetisnull(res, j, i)) {
                value.data = (u_char *)PQgetvalue(res, j, i);
                value.len = PQgetlength(res, j, i);
            } else {
                value.data = NULL;
                value.len = 0;
            }
            
            cfml_query_set_cell(result->query, &col_name, j + 1,
                                cfml_create_string(ctx->pool, &value));
        }
    }
    
    PQclear(res);
    
    result->success = 1;
    result->affected_rows = num_rows;
    
    return result;
}

ngx_int_t
cfml_pgsql_escape_string(ngx_pool_t *pool, cfml_db_connection_t *conn,
                          ngx_str_t *input, ngx_str_t *output)
{
    PGconn *pg = (PGconn *)conn->pg_conn;
    int error;
    
    output->data = ngx_pnalloc(pool, input->len * 2 + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }
    
    output->len = PQescapeStringConn(pg, (char *)output->data,
                                      (char *)input->data, input->len, &error);
    
    return error ? NGX_ERROR : NGX_OK;
}

#else /* !HAVE_PGSQL */

ngx_int_t cfml_pgsql_init(void) { return NGX_OK; }
void cfml_pgsql_cleanup(void) { }
cfml_db_connection_t *cfml_pgsql_connect(ngx_pool_t *pool, ngx_str_t *host,
    ngx_uint_t port, ngx_str_t *database, ngx_str_t *username, ngx_str_t *password)
    { return NULL; }
ngx_int_t cfml_pgsql_disconnect(cfml_db_connection_t *conn) { return NGX_ERROR; }
ngx_int_t cfml_pgsql_ping(cfml_db_connection_t *conn) { return NGX_ERROR; }
cfml_db_result_t *cfml_pgsql_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
    ngx_str_t *sql, ngx_array_t *params) { return NULL; }
ngx_int_t cfml_pgsql_escape_string(ngx_pool_t *pool, cfml_db_connection_t *conn,
    ngx_str_t *input, ngx_str_t *output) { return NGX_ERROR; }

#endif /* HAVE_PGSQL */

/* ===== SQLite Implementation ===== */

#ifdef HAVE_SQLITE

ngx_int_t
cfml_sqlite_init(void)
{
    /* SQLite is self-contained, no global init needed */
    return NGX_OK;
}

void
cfml_sqlite_cleanup(void)
{
    sqlite3_shutdown();
}

cfml_db_connection_t *
cfml_sqlite_connect(ngx_pool_t *pool, ngx_str_t *database)
{
    cfml_db_connection_t *conn;
    sqlite3 *db;
    u_char *db_path;
    int rc;
    
    conn = ngx_pcalloc(pool, sizeof(cfml_db_connection_t));
    if (conn == NULL) {
        return NULL;
    }
    
    /* Null-terminate the database path */
    db_path = ngx_pnalloc(pool, database->len + 1);
    if (db_path == NULL) {
        return NULL;
    }
    ngx_memcpy(db_path, database->data, database->len);
    db_path[database->len] = '\0';
    
    /* Handle special paths */
    if (ngx_strncmp(db_path, "sqlite://", 9) == 0) {
        db_path += 9;
    } else if (ngx_strncmp(db_path, "sqlite3://", 10) == 0) {
        db_path += 10;
    }
    
    /* Support :memory: for in-memory databases */
    rc = sqlite3_open((char *)db_path, &db);
    if (rc != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    
    /* Enable foreign keys */
    sqlite3_exec(db, "PRAGMA foreign_keys = ON", NULL, NULL, NULL);
    
    /* Set UTF-8 encoding */
    sqlite3_exec(db, "PRAGMA encoding = 'UTF-8'", NULL, NULL, NULL);
    
    /* WAL mode for better concurrency */
    sqlite3_exec(db, "PRAGMA journal_mode = WAL", NULL, NULL, NULL);
    
    /* Busy timeout of 5 seconds */
    sqlite3_busy_timeout(db, 5000);
    
    conn->driver = CFML_DB_SQLITE;
    conn->sqlite_conn = db;
    conn->state = CFML_DB_CONN_OPEN;
    conn->pool = pool;
    conn->database = *database;
    
    return conn;
}

ngx_int_t
cfml_sqlite_disconnect(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->sqlite_conn == NULL) {
        return NGX_ERROR;
    }
    
    sqlite3_close((sqlite3 *)conn->sqlite_conn);
    conn->sqlite_conn = NULL;
    conn->state = CFML_DB_CONN_CLOSED;
    
    return NGX_OK;
}

ngx_int_t
cfml_sqlite_ping(cfml_db_connection_t *conn)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    
    if (conn == NULL || conn->sqlite_conn == NULL) {
        return NGX_ERROR;
    }
    
    db = (sqlite3 *)conn->sqlite_conn;
    
    rc = sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return NGX_ERROR;
    }
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
cfml_sqlite_exec(cfml_db_connection_t *conn, ngx_str_t *sql)
{
    sqlite3 *db;
    char *err_msg = NULL;
    u_char *sql_str;
    int rc;
    
    if (conn == NULL || conn->sqlite_conn == NULL) {
        return NGX_ERROR;
    }
    
    db = (sqlite3 *)conn->sqlite_conn;
    
    /* Null-terminate SQL */
    sql_str = ngx_pnalloc(conn->pool, sql->len + 1);
    if (sql_str == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(sql_str, sql->data, sql->len);
    sql_str[sql->len] = '\0';
    
    rc = sqlite3_exec(db, (char *)sql_str, NULL, NULL, &err_msg);
    
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return (rc == SQLITE_OK) ? NGX_OK : NGX_ERROR;
}

int64_t
cfml_sqlite_last_insert_id(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->sqlite_conn == NULL) {
        return 0;
    }
    
    return sqlite3_last_insert_rowid((sqlite3 *)conn->sqlite_conn);
}

ngx_int_t
cfml_sqlite_changes(cfml_db_connection_t *conn)
{
    if (conn == NULL || conn->sqlite_conn == NULL) {
        return 0;
    }
    
    return sqlite3_changes((sqlite3 *)conn->sqlite_conn);
}

cfml_db_result_t *
cfml_sqlite_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
                   ngx_str_t *sql, ngx_array_t *params)
{
    cfml_db_result_t *result;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc, col_count, col_type;
    int i;
    u_char *sql_str;
    ngx_str_t col_name;
    cfml_value_t *cell;
    
    (void)params;  /* TODO: implement parameter binding */
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_db_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    db = (sqlite3 *)conn->sqlite_conn;
    
    /* Null-terminate SQL */
    sql_str = ngx_pnalloc(ctx->pool, sql->len + 1);
    if (sql_str == NULL) {
        result->success = 0;
        ngx_str_set(&result->error, "Memory allocation failed");
        return result;
    }
    ngx_memcpy(sql_str, sql->data, sql->len);
    sql_str[sql->len] = '\0';
    
    rc = sqlite3_prepare_v2(db, (char *)sql_str, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        result->success = 0;
        result->error.data = (u_char *)sqlite3_errmsg(db);
        result->error.len = ngx_strlen(result->error.data);
        return result;
    }
    
    col_count = sqlite3_column_count(stmt);
    
    /* If no columns, this is an INSERT/UPDATE/DELETE */
    if (col_count == 0) {
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        result->success = (rc == SQLITE_DONE);
        result->affected_rows = sqlite3_changes(db);
        result->insert_id = sqlite3_last_insert_rowid(db);
        
        if (!result->success) {
            result->error.data = (u_char *)sqlite3_errmsg(db);
            result->error.len = ngx_strlen(result->error.data);
        }
        
        return result;
    }
    
    /* Create query result for SELECT */
    result->query = cfml_query_new(ctx->pool);
    if (result->query == NULL) {
        sqlite3_finalize(stmt);
        result->success = 0;
        ngx_str_set(&result->error, "Failed to create query result");
        return result;
    }
    
    /* Add columns */
    for (i = 0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);
        col_name.data = (u_char *)name;
        col_name.len = ngx_strlen(name);
        cfml_query_add_column(result->query, &col_name, CFML_TYPE_STRING);
    }
    
    /* Fetch rows */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cfml_query_add_row(result->query);
        
        for (i = 0; i < col_count; i++) {
            const char *name = sqlite3_column_name(stmt, i);
            col_name.data = (u_char *)name;
            col_name.len = ngx_strlen(name);
            
            col_type = sqlite3_column_type(stmt, i);
            
            switch (col_type) {
            case SQLITE_NULL:
                cell = cfml_create_null(ctx->pool);
                break;
                
            case SQLITE_INTEGER:
                cell = cfml_create_integer(ctx->pool, sqlite3_column_int64(stmt, i));
                break;
                
            case SQLITE_FLOAT:
                cell = cfml_create_float(ctx->pool, sqlite3_column_double(stmt, i));
                break;
                
            case SQLITE_BLOB:
                {
                    const void *blob = sqlite3_column_blob(stmt, i);
                    int blob_len = sqlite3_column_bytes(stmt, i);
                    cell = cfml_create_binary(ctx->pool, (u_char *)blob, blob_len);
                }
                break;
                
            case SQLITE_TEXT:
            default:
                {
                    const unsigned char *text = sqlite3_column_text(stmt, i);
                    ngx_str_t str;
                    str.data = (u_char *)text;
                    str.len = ngx_strlen(text);
                    cell = cfml_create_string(ctx->pool, &str);
                }
                break;
            }
            
            cfml_query_set_cell(result->query, &col_name,
                                result->query->row_count, cell);
        }
    }
    
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        result->success = 0;
        result->error.data = (u_char *)sqlite3_errmsg(db);
        result->error.len = ngx_strlen(result->error.data);
        return result;
    }
    
    result->success = 1;
    result->affected_rows = result->query->row_count;
    
    return result;
}

ngx_int_t
cfml_sqlite_escape_string(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *output)
{
    u_char *src, *dst, *end;
    size_t len;
    
    /* Count escaped length */
    len = 0;
    src = input->data;
    end = input->data + input->len;
    
    while (src < end) {
        if (*src == '\'') {
            len += 2;  /* ' -> '' */
        } else {
            len++;
        }
        src++;
    }
    
    output->data = ngx_pnalloc(pool, len + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }
    
    src = input->data;
    dst = output->data;
    
    while (src < end) {
        if (*src == '\'') {
            *dst++ = '\'';
            *dst++ = '\'';
        } else {
            *dst++ = *src;
        }
        src++;
    }
    
    *dst = '\0';
    output->len = len;
    
    return NGX_OK;
}

#else /* !HAVE_SQLITE */

ngx_int_t cfml_sqlite_init(void) { return NGX_OK; }
void cfml_sqlite_cleanup(void) { }
cfml_db_connection_t *cfml_sqlite_connect(ngx_pool_t *pool, ngx_str_t *database)
    { (void)pool; (void)database; return NULL; }
ngx_int_t cfml_sqlite_disconnect(cfml_db_connection_t *conn)
    { (void)conn; return NGX_ERROR; }
ngx_int_t cfml_sqlite_ping(cfml_db_connection_t *conn)
    { (void)conn; return NGX_ERROR; }
cfml_db_result_t *cfml_sqlite_query(cfml_context_t *ctx, cfml_db_connection_t *conn,
    ngx_str_t *sql, ngx_array_t *params)
    { (void)ctx; (void)conn; (void)sql; (void)params; return NULL; }
ngx_int_t cfml_sqlite_escape_string(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *output)
    { (void)pool; (void)input; (void)output; return NGX_ERROR; }
ngx_int_t cfml_sqlite_exec(cfml_db_connection_t *conn, ngx_str_t *sql)
    { (void)conn; (void)sql; return NGX_ERROR; }
int64_t cfml_sqlite_last_insert_id(cfml_db_connection_t *conn)
    { (void)conn; return 0; }
ngx_int_t cfml_sqlite_changes(cfml_db_connection_t *conn)
    { (void)conn; return 0; }

#endif /* HAVE_SQLITE */
