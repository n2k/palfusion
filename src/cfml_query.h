/*
 * CFML Query - Database operations
 */

#ifndef _CFML_QUERY_H_
#define _CFML_QUERY_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Database connection management */
ngx_int_t cfml_db_init(ngx_cycle_t *cycle);
void cfml_db_cleanup(ngx_cycle_t *cycle);

/* Connection pool */
ngx_int_t cfml_db_get_connection(ngx_str_t *datasource, void **conn);
ngx_int_t cfml_db_release_connection(void *conn);

/* Query execution */
ngx_int_t cfml_db_execute_query(cfml_context_t *ctx, ngx_str_t *datasource,
                                ngx_str_t *sql, ngx_array_t *params,
                                cfml_query_t **result);

/* Transaction support */
ngx_int_t cfml_db_begin_transaction(cfml_context_t *ctx, ngx_str_t *datasource);
ngx_int_t cfml_db_commit_transaction(cfml_context_t *ctx);
ngx_int_t cfml_db_rollback_transaction(cfml_context_t *ctx);
ngx_int_t cfml_db_savepoint(cfml_context_t *ctx, ngx_str_t *name);
ngx_int_t cfml_db_rollback_to_savepoint(cfml_context_t *ctx, ngx_str_t *name);

/* Stored procedure support */
ngx_int_t cfml_db_execute_storedproc(cfml_context_t *ctx, ngx_str_t *datasource,
                                     ngx_str_t *procedure, ngx_array_t *params,
                                     ngx_array_t **results);

/* Query parameter types */
typedef enum {
    CFML_PARAM_STRING = 0,
    CFML_PARAM_INTEGER,
    CFML_PARAM_FLOAT,
    CFML_PARAM_DATE,
    CFML_PARAM_TIMESTAMP,
    CFML_PARAM_BOOLEAN,
    CFML_PARAM_BINARY,
    CFML_PARAM_CLOB,
    CFML_PARAM_BLOB,
    CFML_PARAM_NULL
} cfml_param_type_t;

/* Query parameter */
typedef struct {
    cfml_value_t        *value;
    cfml_param_type_t   type;
    ngx_int_t           max_length;
    ngx_int_t           scale;
    unsigned            null:1;
    unsigned            list:1;
    ngx_str_t           separator;
} cfml_query_param_t;

/* Prepared statement support */
typedef struct cfml_prepared_stmt_s cfml_prepared_stmt_t;

cfml_prepared_stmt_t *cfml_db_prepare(cfml_context_t *ctx, ngx_str_t *datasource,
                                      ngx_str_t *sql);
ngx_int_t cfml_db_execute_prepared(cfml_context_t *ctx, cfml_prepared_stmt_t *stmt,
                                   ngx_array_t *params, cfml_query_t **result);
ngx_int_t cfml_db_close_prepared(cfml_prepared_stmt_t *stmt);

/* Query of queries (QoQ) */
ngx_int_t cfml_qoq_execute(cfml_context_t *ctx, ngx_str_t *sql, 
                           cfml_query_t **result);

/* SQL parsing and validation */
ngx_int_t cfml_sql_parse(ngx_pool_t *pool, ngx_str_t *sql, ngx_array_t **params);
ngx_int_t cfml_sql_validate(ngx_str_t *sql);
ngx_int_t cfml_sql_escape_string(ngx_pool_t *pool, ngx_str_t *input, 
                                 ngx_str_t *output);

/* Datasource configuration parsing */
ngx_int_t cfml_parse_connection_string(ngx_pool_t *pool, ngx_str_t *conn_str,
                                       cfml_datasource_t *ds);

#endif /* _CFML_QUERY_H_ */
