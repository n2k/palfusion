/*
 * CFML Variables - Variable scope management
 */

#ifndef _CFML_VARIABLES_H_
#define _CFML_VARIABLES_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Scope initialization */
ngx_int_t cfml_init_scopes(cfml_context_t *ctx);
ngx_int_t cfml_parse_url_params(cfml_context_t *ctx);
ngx_int_t cfml_parse_form_data(cfml_context_t *ctx);
ngx_int_t cfml_populate_cgi_scope(cfml_context_t *ctx);
ngx_int_t cfml_parse_cookies(cfml_context_t *ctx);
ngx_int_t cfml_init_session(cfml_context_t *ctx, ngx_msec_t timeout);

/* Variable operations */
cfml_value_t *cfml_get_variable(cfml_context_t *ctx, ngx_str_t *name);
cfml_value_t *cfml_get_scoped_variable(cfml_context_t *ctx, cfml_scope_type_t scope,
                                       ngx_str_t *name);
ngx_int_t cfml_set_variable(cfml_context_t *ctx, ngx_str_t *name, cfml_value_t *value);
ngx_int_t cfml_set_scoped_variable(cfml_context_t *ctx, cfml_scope_type_t scope,
                                   ngx_str_t *name, cfml_value_t *value);
ngx_int_t cfml_delete_variable(cfml_context_t *ctx, ngx_str_t *name);
ngx_int_t cfml_variable_exists(cfml_context_t *ctx, ngx_str_t *name);

/* Variable path operations (e.g., "struct.key.nested") */
cfml_value_t *cfml_get_variable_path(cfml_context_t *ctx, ngx_str_t *path);
ngx_int_t cfml_set_variable_path(cfml_context_t *ctx, ngx_str_t *path, 
                                  cfml_value_t *value);
ngx_int_t cfml_resolve_variable_path(cfml_context_t *ctx, ngx_str_t *path,
                                      cfml_scope_type_t *scope, ngx_str_t *name);

/* Scope operations */
cfml_struct_t *cfml_get_scope(cfml_context_t *ctx, cfml_scope_type_t scope);
ngx_int_t cfml_push_scope(cfml_context_t *ctx);
ngx_int_t cfml_pop_scope(cfml_context_t *ctx);

/* Value creation helpers */
cfml_value_t *cfml_create_null(ngx_pool_t *pool);
cfml_value_t *cfml_create_boolean(ngx_pool_t *pool, ngx_int_t value);
cfml_value_t *cfml_create_integer(ngx_pool_t *pool, int64_t value);
cfml_value_t *cfml_create_float(ngx_pool_t *pool, double value);
cfml_value_t *cfml_create_string(ngx_pool_t *pool, ngx_str_t *value);
cfml_value_t *cfml_create_string_cstr(ngx_pool_t *pool, const char *value);
cfml_value_t *cfml_create_date(ngx_pool_t *pool, time_t value);
cfml_value_t *cfml_create_array(ngx_pool_t *pool);
cfml_value_t *cfml_create_struct(ngx_pool_t *pool);
cfml_value_t *cfml_create_query(ngx_pool_t *pool);
cfml_value_t *cfml_create_binary(ngx_pool_t *pool, u_char *data, size_t len);

/* Array operations */
cfml_array_t *cfml_array_new(ngx_pool_t *pool, size_t capacity);
ngx_int_t cfml_array_append(cfml_array_t *arr, cfml_value_t *value);
ngx_int_t cfml_array_prepend(cfml_array_t *arr, cfml_value_t *value);
ngx_int_t cfml_array_insert_at(cfml_array_t *arr, ngx_uint_t index, cfml_value_t *value);
ngx_int_t cfml_array_delete_at(cfml_array_t *arr, ngx_uint_t index);
cfml_value_t *cfml_array_get(cfml_array_t *arr, ngx_uint_t index);
ngx_int_t cfml_array_set(cfml_array_t *arr, ngx_uint_t index, cfml_value_t *value);
size_t cfml_array_len(cfml_array_t *arr);
ngx_int_t cfml_array_clear(cfml_array_t *arr);

/* Struct operations */
cfml_struct_t *cfml_struct_new(ngx_pool_t *pool);
ngx_int_t cfml_struct_set(cfml_struct_t *s, ngx_str_t *key, cfml_value_t *value);
cfml_value_t *cfml_struct_get(cfml_struct_t *s, ngx_str_t *key);
ngx_int_t cfml_struct_delete(cfml_struct_t *s, ngx_str_t *key);
ngx_int_t cfml_struct_exists(cfml_struct_t *s, ngx_str_t *key);
ngx_int_t cfml_struct_clear(cfml_struct_t *s);
size_t cfml_struct_count(cfml_struct_t *s);
ngx_array_t *cfml_struct_keys(cfml_struct_t *s);
cfml_struct_t *cfml_struct_copy(ngx_pool_t *pool, cfml_struct_t *s);

/* Query operations */
cfml_query_t *cfml_query_new(ngx_pool_t *pool);
ngx_int_t cfml_query_add_column(cfml_query_t *q, ngx_str_t *name, cfml_type_t type);
ngx_int_t cfml_query_add_row(cfml_query_t *q);
ngx_int_t cfml_query_set_cell(cfml_query_t *q, ngx_str_t *column, ngx_uint_t row,
                               cfml_value_t *value);
cfml_value_t *cfml_query_get_cell(cfml_query_t *q, ngx_str_t *column, ngx_uint_t row);
size_t cfml_query_row_count(cfml_query_t *q);
ngx_array_t *cfml_query_column_list(cfml_query_t *q);

/* Value duplication */
cfml_value_t *cfml_value_duplicate(ngx_pool_t *pool, cfml_value_t *value);

/* Value type checking */
ngx_int_t cfml_value_is_null(cfml_value_t *value);
ngx_int_t cfml_value_is_simple(cfml_value_t *value);
ngx_int_t cfml_value_is_numeric(cfml_value_t *value);

/* Scope name lookup */
cfml_scope_type_t cfml_scope_from_name(ngx_str_t *name);
const char *cfml_scope_name(cfml_scope_type_t scope);

#endif /* _CFML_VARIABLES_H_ */
