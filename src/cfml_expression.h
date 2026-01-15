/*
 * CFML Expression - Expression evaluation
 */

#ifndef _CFML_EXPRESSION_H_
#define _CFML_EXPRESSION_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Expression evaluation */
cfml_value_t *cfml_expr_evaluate(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Binary operations */
cfml_value_t *cfml_expr_add(cfml_context_t *ctx, cfml_value_t *left, 
                            cfml_value_t *right);
cfml_value_t *cfml_expr_subtract(cfml_context_t *ctx, cfml_value_t *left,
                                  cfml_value_t *right);
cfml_value_t *cfml_expr_multiply(cfml_context_t *ctx, cfml_value_t *left,
                                  cfml_value_t *right);
cfml_value_t *cfml_expr_divide(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);
cfml_value_t *cfml_expr_modulo(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);
cfml_value_t *cfml_expr_power(cfml_context_t *ctx, cfml_value_t *left,
                               cfml_value_t *right);
cfml_value_t *cfml_expr_intdiv(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);
cfml_value_t *cfml_expr_concat(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);

/* Comparison operations */
cfml_value_t *cfml_expr_eq(cfml_context_t *ctx, cfml_value_t *left,
                           cfml_value_t *right);
cfml_value_t *cfml_expr_neq(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);
cfml_value_t *cfml_expr_lt(cfml_context_t *ctx, cfml_value_t *left,
                           cfml_value_t *right);
cfml_value_t *cfml_expr_lte(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);
cfml_value_t *cfml_expr_gt(cfml_context_t *ctx, cfml_value_t *left,
                           cfml_value_t *right);
cfml_value_t *cfml_expr_gte(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);

/* Logical operations */
cfml_value_t *cfml_expr_and(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);
cfml_value_t *cfml_expr_or(cfml_context_t *ctx, cfml_value_t *left,
                           cfml_value_t *right);
cfml_value_t *cfml_expr_xor(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);
cfml_value_t *cfml_expr_eqv(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);
cfml_value_t *cfml_expr_imp(cfml_context_t *ctx, cfml_value_t *left,
                            cfml_value_t *right);

/* String operations */
cfml_value_t *cfml_expr_contains(cfml_context_t *ctx, cfml_value_t *left,
                                  cfml_value_t *right);
cfml_value_t *cfml_expr_not_contains(cfml_context_t *ctx, cfml_value_t *left,
                                      cfml_value_t *right);

/* Bitwise operations */
cfml_value_t *cfml_expr_bitand(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);
cfml_value_t *cfml_expr_bitor(cfml_context_t *ctx, cfml_value_t *left,
                               cfml_value_t *right);
cfml_value_t *cfml_expr_bitxor(cfml_context_t *ctx, cfml_value_t *left,
                                cfml_value_t *right);

/* Unary operations */
cfml_value_t *cfml_expr_not(cfml_context_t *ctx, cfml_value_t *operand);
cfml_value_t *cfml_expr_neg(cfml_context_t *ctx, cfml_value_t *operand);
cfml_value_t *cfml_expr_pos(cfml_context_t *ctx, cfml_value_t *operand);
cfml_value_t *cfml_expr_bitnot(cfml_context_t *ctx, cfml_value_t *operand);

/* Type coercion */
cfml_value_t *cfml_coerce_to_numeric(cfml_context_t *ctx, cfml_value_t *value);
cfml_value_t *cfml_coerce_to_string(cfml_context_t *ctx, cfml_value_t *value);
cfml_value_t *cfml_coerce_to_boolean(cfml_context_t *ctx, cfml_value_t *value);
cfml_value_t *cfml_coerce_to_date(cfml_context_t *ctx, cfml_value_t *value);

/* Comparison helpers */
ngx_int_t cfml_compare_strings(ngx_str_t *a, ngx_str_t *b);
ngx_int_t cfml_compare_strings_nocase(ngx_str_t *a, ngx_str_t *b);
ngx_int_t cfml_compare_numbers(cfml_value_t *a, cfml_value_t *b);

#endif /* _CFML_EXPRESSION_H_ */
