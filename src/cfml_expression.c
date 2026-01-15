/*
 * CFML Expression - Expression evaluation implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>
#include "cfml_expression.h"
#include "cfml_variables.h"
#include "cfml_runtime.h"

/* Helper to get numeric values */
static ngx_int_t
cfml_get_numeric_operands(cfml_context_t *ctx, cfml_value_t *left, 
                          cfml_value_t *right, double *l, double *r)
{
    if (cfml_value_to_float(left, l) != NGX_OK) {
        return NGX_ERROR;
    }
    if (cfml_value_to_float(right, r) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Addition */
cfml_value_t *
cfml_expr_add(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    /* String concatenation if both are strings */
    if (left->type == CFML_TYPE_STRING && right->type == CFML_TYPE_STRING) {
        return cfml_expr_concat(ctx, left, right);
    }

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    /* Return integer if both operands were integers */
    if (left->type == CFML_TYPE_INTEGER && right->type == CFML_TYPE_INTEGER) {
        return cfml_create_integer(ctx->pool, (int64_t)(l + r));
    }

    return cfml_create_float(ctx->pool, l + r);
}

/* Subtraction */
cfml_value_t *
cfml_expr_subtract(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (left->type == CFML_TYPE_INTEGER && right->type == CFML_TYPE_INTEGER) {
        return cfml_create_integer(ctx->pool, (int64_t)(l - r));
    }

    return cfml_create_float(ctx->pool, l - r);
}

/* Multiplication */
cfml_value_t *
cfml_expr_multiply(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (left->type == CFML_TYPE_INTEGER && right->type == CFML_TYPE_INTEGER) {
        return cfml_create_integer(ctx->pool, (int64_t)(l * r));
    }

    return cfml_create_float(ctx->pool, l * r);
}

/* Division */
cfml_value_t *
cfml_expr_divide(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (r == 0.0) {
        ngx_str_set(&ctx->error_message, "Division by zero");
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_float(ctx->pool, l / r);
}

/* Modulo */
cfml_value_t *
cfml_expr_modulo(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (r == 0.0) {
        ngx_str_set(&ctx->error_message, "Division by zero");
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_float(ctx->pool, fmod(l, r));
}

/* Power */
cfml_value_t *
cfml_expr_power(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_float(ctx->pool, pow(l, r));
}

/* Integer division */
cfml_value_t *
cfml_expr_intdiv(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    double l, r;

    if (cfml_get_numeric_operands(ctx, left, right, &l, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (r == 0.0) {
        ngx_str_set(&ctx->error_message, "Division by zero");
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_integer(ctx->pool, (int64_t)(l / r));
}

/* String concatenation */
cfml_value_t *
cfml_expr_concat(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    ngx_str_t ls, rs, result;

    if (cfml_value_to_string(ctx, left, &ls) != NGX_OK ||
        cfml_value_to_string(ctx, right, &rs) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    result.len = ls.len + rs.len;
    result.data = ngx_pnalloc(ctx->pool, result.len + 1);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }

    ngx_memcpy(result.data, ls.data, ls.len);
    ngx_memcpy(result.data + ls.len, rs.data, rs.len);
    result.data[result.len] = '\0';

    return cfml_create_string(ctx->pool, &result);
}

/* Equality */
cfml_value_t *
cfml_expr_eq(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, cfml_values_equal(left, right));
}

/* Not equal */
cfml_value_t *
cfml_expr_neq(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, !cfml_values_equal(left, right));
}

/* Less than */
cfml_value_t *
cfml_expr_lt(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, cfml_compare_values(left, right) < 0);
}

/* Less than or equal */
cfml_value_t *
cfml_expr_lte(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, cfml_compare_values(left, right) <= 0);
}

/* Greater than */
cfml_value_t *
cfml_expr_gt(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, cfml_compare_values(left, right) > 0);
}

/* Greater than or equal */
cfml_value_t *
cfml_expr_gte(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, cfml_compare_values(left, right) >= 0);
}

/* Logical AND */
cfml_value_t *
cfml_expr_and(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool, 
        cfml_value_to_boolean(left) && cfml_value_to_boolean(right));
}

/* Logical OR */
cfml_value_t *
cfml_expr_or(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    return cfml_create_boolean(ctx->pool,
        cfml_value_to_boolean(left) || cfml_value_to_boolean(right));
}

/* Logical XOR */
cfml_value_t *
cfml_expr_xor(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    ngx_int_t l = cfml_value_to_boolean(left);
    ngx_int_t r = cfml_value_to_boolean(right);
    return cfml_create_boolean(ctx->pool, (l && !r) || (!l && r));
}

/* Logical EQV (equivalence) */
cfml_value_t *
cfml_expr_eqv(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    ngx_int_t l = cfml_value_to_boolean(left);
    ngx_int_t r = cfml_value_to_boolean(right);
    return cfml_create_boolean(ctx->pool, l == r);
}

/* Logical IMP (implication) */
cfml_value_t *
cfml_expr_imp(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    ngx_int_t l = cfml_value_to_boolean(left);
    ngx_int_t r = cfml_value_to_boolean(right);
    return cfml_create_boolean(ctx->pool, !l || r);
}

/* String contains */
cfml_value_t *
cfml_expr_contains(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    ngx_str_t ls, rs;

    if (cfml_value_to_string(ctx, left, &ls) != NGX_OK ||
        cfml_value_to_string(ctx, right, &rs) != NGX_OK) {
        return cfml_create_boolean(ctx->pool, 0);
    }

    if (rs.len == 0) {
        return cfml_create_boolean(ctx->pool, 1);
    }

    if (ls.len < rs.len) {
        return cfml_create_boolean(ctx->pool, 0);
    }

    /* Case-insensitive search */
    u_char *p = ls.data;
    u_char *end = ls.data + ls.len - rs.len + 1;

    while (p < end) {
        if (ngx_strncasecmp(p, rs.data, rs.len) == 0) {
            return cfml_create_boolean(ctx->pool, 1);
        }
        p++;
    }

    return cfml_create_boolean(ctx->pool, 0);
}

/* String does not contain */
cfml_value_t *
cfml_expr_not_contains(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    cfml_value_t *result = cfml_expr_contains(ctx, left, right);
    if (result == NULL) {
        return NULL;
    }
    return cfml_create_boolean(ctx->pool, !result->data.boolean);
}

/* Bitwise AND */
cfml_value_t *
cfml_expr_bitand(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    int64_t l, r;

    if (cfml_value_to_integer(left, &l) != NGX_OK ||
        cfml_value_to_integer(right, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_integer(ctx->pool, l & r);
}

/* Bitwise OR */
cfml_value_t *
cfml_expr_bitor(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    int64_t l, r;

    if (cfml_value_to_integer(left, &l) != NGX_OK ||
        cfml_value_to_integer(right, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_integer(ctx->pool, l | r);
}

/* Bitwise XOR */
cfml_value_t *
cfml_expr_bitxor(cfml_context_t *ctx, cfml_value_t *left, cfml_value_t *right)
{
    int64_t l, r;

    if (cfml_value_to_integer(left, &l) != NGX_OK ||
        cfml_value_to_integer(right, &r) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_integer(ctx->pool, l ^ r);
}

/* Logical NOT */
cfml_value_t *
cfml_expr_not(cfml_context_t *ctx, cfml_value_t *operand)
{
    return cfml_create_boolean(ctx->pool, !cfml_value_to_boolean(operand));
}

/* Numeric negation */
cfml_value_t *
cfml_expr_neg(cfml_context_t *ctx, cfml_value_t *operand)
{
    double val;

    if (cfml_value_to_float(operand, &val) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (operand->type == CFML_TYPE_INTEGER) {
        return cfml_create_integer(ctx->pool, -(int64_t)val);
    }

    return cfml_create_float(ctx->pool, -val);
}

/* Numeric positive (no-op but enforces numeric) */
cfml_value_t *
cfml_expr_pos(cfml_context_t *ctx, cfml_value_t *operand)
{
    double val;

    if (cfml_value_to_float(operand, &val) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    if (operand->type == CFML_TYPE_INTEGER) {
        return cfml_create_integer(ctx->pool, (int64_t)val);
    }

    return cfml_create_float(ctx->pool, val);
}

/* Bitwise NOT */
cfml_value_t *
cfml_expr_bitnot(cfml_context_t *ctx, cfml_value_t *operand)
{
    int64_t val;

    if (cfml_value_to_integer(operand, &val) != NGX_OK) {
        return cfml_create_null(ctx->pool);
    }

    return cfml_create_integer(ctx->pool, ~val);
}

/* Compare two values */
ngx_int_t
cfml_compare_values(cfml_value_t *a, cfml_value_t *b)
{
    /* Handle null */
    if (a == NULL || a->is_null) {
        if (b == NULL || b->is_null) {
            return 0;
        }
        return -1;
    }
    if (b == NULL || b->is_null) {
        return 1;
    }

    /* Numeric comparison */
    if ((a->type == CFML_TYPE_INTEGER || a->type == CFML_TYPE_FLOAT) &&
        (b->type == CFML_TYPE_INTEGER || b->type == CFML_TYPE_FLOAT)) {
        double av, bv;
        cfml_value_to_float(a, &av);
        cfml_value_to_float(b, &bv);
        
        if (av < bv) return -1;
        if (av > bv) return 1;
        return 0;
    }

    /* String comparison (case-insensitive by default in CFML) */
    if (a->type == CFML_TYPE_STRING && b->type == CFML_TYPE_STRING) {
        return cfml_compare_strings_nocase(&a->data.string, &b->data.string);
    }

    /* Date comparison */
    if (a->type == CFML_TYPE_DATE && b->type == CFML_TYPE_DATE) {
        if (a->data.date.time < b->data.date.time) return -1;
        if (a->data.date.time > b->data.date.time) return 1;
        return 0;
    }

    /* Mixed types - try numeric then string */
    double av, bv;
    if (cfml_value_to_float(a, &av) == NGX_OK &&
        cfml_value_to_float(b, &bv) == NGX_OK) {
        if (av < bv) return -1;
        if (av > bv) return 1;
        return 0;
    }

    /* Fall back to string comparison */
    ngx_str_t as, bs;
    /* Note: This is simplified - full implementation would need proper context */
    as = a->data.string;
    bs = b->data.string;
    return cfml_compare_strings_nocase(&as, &bs);
}

/* Check if two values are equal */
ngx_int_t
cfml_values_equal(cfml_value_t *a, cfml_value_t *b)
{
    /* Handle null */
    if ((a == NULL || a->is_null) && (b == NULL || b->is_null)) {
        return 1;
    }
    if (a == NULL || a->is_null || b == NULL || b->is_null) {
        return 0;
    }

    /* Same type comparison */
    if (a->type == b->type) {
        switch (a->type) {
        case CFML_TYPE_BOOLEAN:
            return a->data.boolean == b->data.boolean;
            
        case CFML_TYPE_INTEGER:
            return a->data.integer == b->data.integer;
            
        case CFML_TYPE_FLOAT:
            return a->data.floating == b->data.floating;
            
        case CFML_TYPE_STRING:
            return (a->data.string.len == b->data.string.len &&
                    ngx_strncasecmp(a->data.string.data, b->data.string.data,
                                    a->data.string.len) == 0);
            
        case CFML_TYPE_DATE:
            return a->data.date.time == b->data.date.time;
            
        case CFML_TYPE_ARRAY:
        case CFML_TYPE_STRUCT:
        case CFML_TYPE_QUERY:
        case CFML_TYPE_COMPONENT:
            /* Reference equality */
            return a == b;
            
        default:
            return 0;
        }
    }

    /* Cross-type comparison */
    /* Numeric types */
    if ((a->type == CFML_TYPE_INTEGER || a->type == CFML_TYPE_FLOAT) &&
        (b->type == CFML_TYPE_INTEGER || b->type == CFML_TYPE_FLOAT)) {
        double av, bv;
        cfml_value_to_float(a, &av);
        cfml_value_to_float(b, &bv);
        return av == bv;
    }

    /* String to number comparison */
    if ((a->type == CFML_TYPE_STRING && 
         (b->type == CFML_TYPE_INTEGER || b->type == CFML_TYPE_FLOAT)) ||
        (b->type == CFML_TYPE_STRING &&
         (a->type == CFML_TYPE_INTEGER || a->type == CFML_TYPE_FLOAT))) {
        double av, bv;
        if (cfml_value_to_float(a, &av) == NGX_OK &&
            cfml_value_to_float(b, &bv) == NGX_OK) {
            return av == bv;
        }
    }

    /* Boolean comparison */
    if (a->type == CFML_TYPE_BOOLEAN || b->type == CFML_TYPE_BOOLEAN) {
        return cfml_value_to_boolean(a) == cfml_value_to_boolean(b);
    }

    return 0;
}

/* Compare strings case-sensitive */
ngx_int_t
cfml_compare_strings(ngx_str_t *a, ngx_str_t *b)
{
    size_t min_len = (a->len < b->len) ? a->len : b->len;
    ngx_int_t result = ngx_memcmp(a->data, b->data, min_len);
    
    if (result == 0) {
        if (a->len < b->len) return -1;
        if (a->len > b->len) return 1;
    }
    
    return result;
}

/* Compare strings case-insensitive */
ngx_int_t
cfml_compare_strings_nocase(ngx_str_t *a, ngx_str_t *b)
{
    size_t min_len = (a->len < b->len) ? a->len : b->len;
    ngx_int_t result = ngx_strncasecmp(a->data, b->data, min_len);
    
    if (result == 0) {
        if (a->len < b->len) return -1;
        if (a->len > b->len) return 1;
    }
    
    return result;
}

/* Type coercion functions */
cfml_value_t *
cfml_coerce_to_numeric(cfml_context_t *ctx, cfml_value_t *value)
{
    double result;
    
    if (cfml_value_to_float(value, &result) != NGX_OK) {
        return cfml_create_float(ctx->pool, 0.0);
    }
    
    return cfml_create_float(ctx->pool, result);
}

cfml_value_t *
cfml_coerce_to_string(cfml_context_t *ctx, cfml_value_t *value)
{
    ngx_str_t result;
    
    if (cfml_value_to_string(ctx, value, &result) != NGX_OK) {
        ngx_str_set(&result, "");
    }
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *
cfml_coerce_to_boolean(cfml_context_t *ctx, cfml_value_t *value)
{
    return cfml_create_boolean(ctx->pool, cfml_value_to_boolean(value));
}
