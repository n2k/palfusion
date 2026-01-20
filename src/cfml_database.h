/*
 * CFML Database - MySQL, PostgreSQL, and SQLite native connectivity
 */

#ifndef _CFML_DATABASE_H_
#define _CFML_DATABASE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Database driver types */
typedef enum {
    CFML_DB_MYSQL = 0,
    CFML_DB_POSTGRESQL,
    CFML_DB_SQLITE,
    CFML_DB_UNKNOWN
} cfml_db_driver_t;

/* Connection state */
typedef enum {
    CFML_DB_CONN_CLOSED = 0,
    CFML_DB_CONN_OPEN,
    CFML_DB_CONN_ERROR
} cfml_db_conn_state_t;

/* Connection structure */
typedef struct {
    cfml_db_driver_t        driver;
    cfml_db_conn_state_t    state;
    ngx_str_t               name;
    ngx_str_t               host;
    ngx_uint_t              port;
    ngx_str_t               database;
    ngx_str_t               username;
    ngx_str_t               password;
    ngx_str_t               charset;
    ngx_msec_t              timeout;
    ngx_pool_t              *pool;
    
    /* Driver-specific handles */
    void                    *mysql_conn;      /* MYSQL* */
    void                    *pg_conn;         /* PGconn* */
    void                    *sqlite_conn;     /* sqlite3* */
    
    /* Connection pool management */
    ngx_queue_t             queue;
    ngx_msec_t              last_used;
    unsigned                in_use:1;
    unsigned                in_transaction:1;
} cfml_db_connection_t;

/* Connection pool */
typedef struct {
    ngx_str_t               name;
    cfml_db_driver_t        driver;
    ngx_str_t               connection_string;
    ngx_uint_t              min_connections;
    ngx_uint_t              max_connections;
    ngx_uint_t              current_count;
    ngx_msec_t              idle_timeout;
    ngx_queue_t             free_connections;
    ngx_queue_t             used_connections;
    ngx_shmtx_t             mutex;
    ngx_pool_t              *pool;
} cfml_db_pool_t;

/* Query result */
typedef struct {
    cfml_query_t            *query;
    ngx_int_t               affected_rows;
    ngx_int_t               insert_id;
    ngx_str_t               error;
    unsigned                success:1;
} cfml_db_result_t;

/* Query parameter */
typedef struct {
    ngx_str_t               name;
    cfml_value_t            *value;
    ngx_str_t               cfsqltype;
    ngx_str_t               null;
    ngx_int_t               maxlength;
    ngx_int_t               scale;
    unsigned                is_null:1;
    unsigned                is_list:1;
    ngx_str_t               separator;
} cfml_db_param_t;

/* Initialization and cleanup */
ngx_int_t cfml_database_init(ngx_cycle_t *cycle);
void cfml_database_cleanup(ngx_cycle_t *cycle);

/* Pool management */
cfml_db_pool_t *cfml_db_pool_create(ngx_pool_t *pool, ngx_str_t *name,
                                     ngx_str_t *connection_string);
ngx_int_t cfml_db_pool_destroy(cfml_db_pool_t *pool);

/* Connection management */
cfml_db_connection_t *cfml_db_get_connection(cfml_context_t *ctx,
                                              ngx_str_t *datasource);
ngx_int_t cfml_db_release_connection(cfml_db_connection_t *conn);
ngx_int_t cfml_db_close_connection(cfml_db_connection_t *conn);
ngx_int_t cfml_db_ping_connection(cfml_db_connection_t *conn);

/* Query execution */
cfml_db_result_t *cfml_db_execute(cfml_context_t *ctx,
                                   cfml_db_connection_t *conn,
                                   ngx_str_t *sql,
                                   ngx_array_t *params);
cfml_db_result_t *cfml_db_execute_query(cfml_context_t *ctx,
                                         ngx_str_t *datasource,
                                         ngx_str_t *sql,
                                         ngx_array_t *params);

/* Transaction support */
ngx_int_t cfml_db_begin_transaction(cfml_db_connection_t *conn);
ngx_int_t cfml_db_commit(cfml_db_connection_t *conn);
ngx_int_t cfml_db_rollback(cfml_db_connection_t *conn);
ngx_int_t cfml_db_savepoint(cfml_db_connection_t *conn, ngx_str_t *name);
ngx_int_t cfml_db_rollback_to_savepoint(cfml_db_connection_t *conn,
                                         ngx_str_t *name);

/* Stored procedures */
cfml_db_result_t *cfml_db_execute_proc(cfml_context_t *ctx,
                                        cfml_db_connection_t *conn,
                                        ngx_str_t *procedure,
                                        ngx_array_t *params);

/* MySQL-specific functions */
ngx_int_t cfml_mysql_init(void);
void cfml_mysql_cleanup(void);
cfml_db_connection_t *cfml_mysql_connect(ngx_pool_t *pool,
                                          ngx_str_t *host,
                                          ngx_uint_t port,
                                          ngx_str_t *database,
                                          ngx_str_t *username,
                                          ngx_str_t *password);
ngx_int_t cfml_mysql_disconnect(cfml_db_connection_t *conn);
cfml_db_result_t *cfml_mysql_query(cfml_context_t *ctx,
                                    cfml_db_connection_t *conn,
                                    ngx_str_t *sql,
                                    ngx_array_t *params);
ngx_int_t cfml_mysql_escape_string(ngx_pool_t *pool,
                                    cfml_db_connection_t *conn,
                                    ngx_str_t *input,
                                    ngx_str_t *output);
ngx_int_t cfml_mysql_ping(cfml_db_connection_t *conn);

/* PostgreSQL-specific functions */
ngx_int_t cfml_pgsql_init(void);
void cfml_pgsql_cleanup(void);
cfml_db_connection_t *cfml_pgsql_connect(ngx_pool_t *pool,
                                          ngx_str_t *host,
                                          ngx_uint_t port,
                                          ngx_str_t *database,
                                          ngx_str_t *username,
                                          ngx_str_t *password);
ngx_int_t cfml_pgsql_disconnect(cfml_db_connection_t *conn);
cfml_db_result_t *cfml_pgsql_query(cfml_context_t *ctx,
                                    cfml_db_connection_t *conn,
                                    ngx_str_t *sql,
                                    ngx_array_t *params);
ngx_int_t cfml_pgsql_escape_string(ngx_pool_t *pool,
                                    cfml_db_connection_t *conn,
                                    ngx_str_t *input,
                                    ngx_str_t *output);
ngx_int_t cfml_pgsql_ping(cfml_db_connection_t *conn);

/* SQLite-specific functions */
ngx_int_t cfml_sqlite_init(void);
void cfml_sqlite_cleanup(void);
cfml_db_connection_t *cfml_sqlite_connect(ngx_pool_t *pool,
                                           ngx_str_t *database);
ngx_int_t cfml_sqlite_disconnect(cfml_db_connection_t *conn);
cfml_db_result_t *cfml_sqlite_query(cfml_context_t *ctx,
                                     cfml_db_connection_t *conn,
                                     ngx_str_t *sql,
                                     ngx_array_t *params);
ngx_int_t cfml_sqlite_escape_string(ngx_pool_t *pool,
                                     ngx_str_t *input,
                                     ngx_str_t *output);
ngx_int_t cfml_sqlite_ping(cfml_db_connection_t *conn);
ngx_int_t cfml_sqlite_exec(cfml_db_connection_t *conn, ngx_str_t *sql);
int64_t cfml_sqlite_last_insert_id(cfml_db_connection_t *conn);
ngx_int_t cfml_sqlite_changes(cfml_db_connection_t *conn);

/* Utility functions */
cfml_db_driver_t cfml_db_parse_driver(ngx_str_t *connection_string);
ngx_int_t cfml_db_parse_connection_string(ngx_pool_t *pool,
                                           ngx_str_t *conn_str,
                                           cfml_db_connection_t *conn);
ngx_str_t *cfml_db_format_param(ngx_pool_t *pool,
                                 cfml_db_param_t *param,
                                 cfml_db_driver_t driver);
ngx_int_t cfml_db_bind_params(ngx_pool_t *pool,
                               ngx_str_t *sql,
                               ngx_array_t *params,
                               cfml_db_driver_t driver,
                               ngx_str_t *result);

#endif /* _CFML_DATABASE_H_ */
