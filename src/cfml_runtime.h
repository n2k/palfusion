/*
 * CFML Runtime - AST execution engine
 */

#ifndef _CFML_RUNTIME_H_
#define _CFML_RUNTIME_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Execution functions */
ngx_int_t cfml_execute(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_execute_children(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Tag execution */
ngx_int_t cfml_execute_tag(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Expression evaluation */
cfml_value_t *cfml_eval_expression(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_binary(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_unary(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_ternary(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_function_call(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_method_call(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_variable(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_array_access(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_struct_access(cfml_context_t *ctx, cfml_ast_node_t *node);
cfml_value_t *cfml_eval_assignment(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Output functions */
ngx_int_t cfml_output_value(cfml_context_t *ctx, cfml_value_t *value);
ngx_int_t cfml_output_string(cfml_context_t *ctx, ngx_str_t *str);
ngx_int_t cfml_output_text(cfml_context_t *ctx, u_char *text, size_t len);

/* Interpolation */
ngx_int_t cfml_interpolate_string(cfml_context_t *ctx, ngx_str_t *input, 
                                  ngx_str_t *output);

/* Control flow */
ngx_int_t cfml_handle_abort(cfml_context_t *ctx);
ngx_int_t cfml_handle_exit(cfml_context_t *ctx);
ngx_int_t cfml_check_control_flow(cfml_context_t *ctx);

/* Exception handling */
ngx_int_t cfml_throw_exception(cfml_context_t *ctx, ngx_str_t *type, 
                               ngx_str_t *message);
ngx_int_t cfml_catch_exception(cfml_context_t *ctx, cfml_ast_node_t *catch_node);
void cfml_clear_exception(cfml_context_t *ctx);

/* Include handling */
ngx_int_t cfml_include_template(cfml_context_t *ctx, ngx_str_t *path);

/* Application.cfc support */
ngx_int_t cfml_load_application_cfc(cfml_context_t *ctx, ngx_str_t *page_path);
ngx_int_t cfml_invoke_application_method(cfml_context_t *ctx, const char *method,
                                         ngx_str_t *arg);

/* Type conversion helpers */
ngx_int_t cfml_value_to_boolean(cfml_value_t *value);
ngx_int_t cfml_value_to_integer(cfml_value_t *value, int64_t *result);
ngx_int_t cfml_value_to_float(cfml_value_t *value, double *result);
ngx_int_t cfml_value_to_string(cfml_context_t *ctx, cfml_value_t *value, 
                               ngx_str_t *result);

/* Comparison */
ngx_int_t cfml_compare_values(cfml_value_t *a, cfml_value_t *b);
ngx_int_t cfml_values_equal(cfml_value_t *a, cfml_value_t *b);

/* Debug */
ngx_int_t cfml_dump_value(cfml_context_t *ctx, cfml_value_t *value, 
                          ngx_str_t *output);

#endif /* _CFML_RUNTIME_H_ */
