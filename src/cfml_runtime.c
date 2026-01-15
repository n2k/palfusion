/*
 * CFML Runtime - AST execution engine
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_runtime.h"
#include "cfml_parser.h"
#include "cfml_tags.h"
#include "cfml_functions.h"
#include "cfml_variables.h"
#include "cfml_expression.h"
#include "cfml_component.h"
#include "cfml_cache.h"

/* Execute AST node */
ngx_int_t
cfml_execute(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    if (node == NULL) {
        return NGX_OK;
    }

    /* Check for abort/exit */
    if (ctx->abort || ctx->exit) {
        return NGX_OK;
    }

    switch (node->type) {
    case CFML_AST_ROOT:
    case CFML_AST_TEMPLATE:
        return cfml_execute_children(ctx, node);

    case CFML_AST_TEXT:
        return cfml_output_text(ctx, node->data.text.data, node->data.text.len);

    case CFML_AST_COMMENT:
        /* Comments produce no output */
        return NGX_OK;

    case CFML_AST_TAG_SET:
    case CFML_AST_TAG_OUTPUT:
    case CFML_AST_TAG_IF:
    case CFML_AST_TAG_LOOP:
    case CFML_AST_TAG_BREAK:
    case CFML_AST_TAG_CONTINUE:
    case CFML_AST_TAG_INCLUDE:
    case CFML_AST_TAG_PARAM:
    case CFML_AST_TAG_FUNCTION:
    case CFML_AST_TAG_RETURN:
    case CFML_AST_TAG_COMPONENT:
    case CFML_AST_TAG_QUERY:
    case CFML_AST_TAG_HTTP:
    case CFML_AST_TAG_TRY:
    case CFML_AST_TAG_THROW:
    case CFML_AST_TAG_SWITCH:
    case CFML_AST_TAG_ABORT:
    case CFML_AST_TAG_EXIT:
    case CFML_AST_TAG_DUMP:
    case CFML_AST_TAG_LOG:
    case CFML_AST_TAG_LOCATION:
    case CFML_AST_TAG_HEADER:
    case CFML_AST_TAG_CONTENT:
    case CFML_AST_TAG_COOKIE:
    case CFML_AST_TAG_SAVECONTENT:
    case CFML_AST_TAG_FILE:
    case CFML_AST_TAG_DIRECTORY:
    case CFML_AST_TAG_MAIL:
    case CFML_AST_TAG_LOCK:
    case CFML_AST_TAG_THREAD:
    case CFML_AST_TAG_TRANSACTION:
    case CFML_AST_TAG_CACHE:
    case CFML_AST_TAG_SETTING:
    case CFML_AST_TAG_SILENT:
    case CFML_AST_TAG_FLUSH:
    case CFML_AST_TAG_CUSTOM:
        return cfml_execute_tag(ctx, node);

    case CFML_AST_SCRIPT:
    case CFML_AST_SCRIPT_BLOCK:
        return cfml_execute_children(ctx, node);

    case CFML_AST_EXPR_INTERPOLATION:
        {
            /* Output interpolated expression */
            cfml_ast_node_t **children;
            cfml_value_t *value;

            if (node->children->nelts == 0) {
                return NGX_OK;
            }

            children = node->children->elts;
            value = cfml_eval_expression(ctx, children[0]);
            if (value == NULL) {
                return NGX_ERROR;
            }

            return cfml_output_value(ctx, value);
        }

    default:
        /* For expression nodes, evaluate and discard result */
        cfml_eval_expression(ctx, node);
        return NGX_OK;
    }
}

/* Execute children nodes */
ngx_int_t
cfml_execute_children(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_ast_node_t **children;
    ngx_uint_t i;
    ngx_int_t rc;

    if (node == NULL || node->children == NULL) {
        return NGX_OK;
    }

    children = node->children->elts;
    for (i = 0; i < node->children->nelts; i++) {
        rc = cfml_execute(ctx, children[i]);
        if (rc != NGX_OK) {
            return rc;
        }

        /* Check control flow flags */
        if (ctx->abort || ctx->exit || ctx->return_ || 
            ctx->break_ || ctx->continue_) {
            break;
        }
    }

    return NGX_OK;
}

/* Execute tag */
ngx_int_t
cfml_execute_tag(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_tag_handler_t handler;

    handler = cfml_get_tag_handler(&node->tag_name);
    if (handler == NULL) {
        ngx_str_set(&ctx->error_message, "Unknown tag");
        ctx->error_line = node->line;
        return NGX_ERROR;
    }

    return handler(ctx, node);
}

/* Evaluate expression */
cfml_value_t *
cfml_eval_expression(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    if (node == NULL) {
        return cfml_create_null(ctx->pool);
    }

    switch (node->type) {
    case CFML_AST_EXPR_LITERAL:
        return node->data.literal;

    case CFML_AST_EXPR_VARIABLE:
        return cfml_eval_variable(ctx, node);

    case CFML_AST_EXPR_BINARY:
        return cfml_eval_binary(ctx, node);

    case CFML_AST_EXPR_UNARY:
    case CFML_AST_EXPR_INCREMENT:
        return cfml_eval_unary(ctx, node);

    case CFML_AST_EXPR_TERNARY:
        return cfml_eval_ternary(ctx, node);

    case CFML_AST_EXPR_FUNCTION_CALL:
        return cfml_eval_function_call(ctx, node);

    case CFML_AST_EXPR_METHOD_CALL:
        return cfml_eval_method_call(ctx, node);

    case CFML_AST_EXPR_ARRAY_ACCESS:
        return cfml_eval_array_access(ctx, node);

    case CFML_AST_EXPR_STRUCT_ACCESS:
        return cfml_eval_struct_access(ctx, node);

    case CFML_AST_EXPR_ASSIGNMENT:
    case CFML_AST_EXPR_COMPOUND_ASSIGNMENT:
        return cfml_eval_assignment(ctx, node);

    case CFML_AST_EXPR_ARRAY_LITERAL:
        {
            cfml_value_t *arr = cfml_create_array(ctx->pool);
            cfml_ast_node_t **children;
            ngx_uint_t i;

            if (arr == NULL) {
                return NULL;
            }

            children = node->children->elts;
            for (i = 0; i < node->children->nelts; i++) {
                cfml_value_t *elem = cfml_eval_expression(ctx, children[i]);
                if (elem == NULL) {
                    return NULL;
                }
                cfml_array_append(arr->data.array, elem);
            }

            return arr;
        }

    case CFML_AST_EXPR_STRUCT_LITERAL:
        {
            cfml_value_t *st = cfml_create_struct(ctx->pool);
            cfml_ast_attr_t *attrs;
            ngx_uint_t i;

            if (st == NULL) {
                return NULL;
            }

            attrs = node->attributes->elts;
            for (i = 0; i < node->attributes->nelts; i++) {
                cfml_value_t *val = cfml_eval_expression(ctx, attrs[i].value);
                if (val == NULL) {
                    return NULL;
                }
                cfml_struct_set(st->data.structure, &attrs[i].name, val);
            }

            return st;
        }

    case CFML_AST_SCRIPT_NEW:
        {
            /* Create new component instance */
            ngx_str_t comp_name = node->data.function_call.name;
            ngx_str_t resolved_path;
            
            if (cfml_resolve_component_path(ctx, &comp_name, &resolved_path) != NGX_OK) {
                ctx->error_message.data = (u_char *)"Component not found";
                ctx->error_message.len = 19;
                return NULL;
            }
            
            return cfml_component_instantiate(ctx, 
                cfml_component_load(ctx, &resolved_path),
                node->data.function_call.args);
        }

    default:
        return cfml_create_null(ctx->pool);
    }
}

/* Evaluate binary expression */
cfml_value_t *
cfml_eval_binary(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *left, *right;

    left = cfml_eval_expression(ctx, node->data.binary.left);
    if (left == NULL) {
        return NULL;
    }

    /* Short-circuit evaluation for AND/OR */
    if (node->data.binary.op == CFML_OP_AND) {
        if (!cfml_value_to_boolean(left)) {
            return cfml_create_boolean(ctx->pool, 0);
        }
    } else if (node->data.binary.op == CFML_OP_OR) {
        if (cfml_value_to_boolean(left)) {
            return cfml_create_boolean(ctx->pool, 1);
        }
    }

    right = cfml_eval_expression(ctx, node->data.binary.right);
    if (right == NULL) {
        return NULL;
    }

    switch (node->data.binary.op) {
    case CFML_OP_ADD:
        return cfml_expr_add(ctx, left, right);
    case CFML_OP_SUB:
        return cfml_expr_subtract(ctx, left, right);
    case CFML_OP_MUL:
        return cfml_expr_multiply(ctx, left, right);
    case CFML_OP_DIV:
        return cfml_expr_divide(ctx, left, right);
    case CFML_OP_MOD:
        return cfml_expr_modulo(ctx, left, right);
    case CFML_OP_POW:
        return cfml_expr_power(ctx, left, right);
    case CFML_OP_INTDIV:
        return cfml_expr_intdiv(ctx, left, right);
    case CFML_OP_CONCAT:
        return cfml_expr_concat(ctx, left, right);
    case CFML_OP_EQ:
        return cfml_expr_eq(ctx, left, right);
    case CFML_OP_NEQ:
        return cfml_expr_neq(ctx, left, right);
    case CFML_OP_LT:
        return cfml_expr_lt(ctx, left, right);
    case CFML_OP_LTE:
        return cfml_expr_lte(ctx, left, right);
    case CFML_OP_GT:
        return cfml_expr_gt(ctx, left, right);
    case CFML_OP_GTE:
        return cfml_expr_gte(ctx, left, right);
    case CFML_OP_AND:
        return cfml_expr_and(ctx, left, right);
    case CFML_OP_OR:
        return cfml_expr_or(ctx, left, right);
    case CFML_OP_XOR:
        return cfml_expr_xor(ctx, left, right);
    case CFML_OP_EQV:
        return cfml_expr_eqv(ctx, left, right);
    case CFML_OP_IMP:
        return cfml_expr_imp(ctx, left, right);
    case CFML_OP_CONTAINS:
        return cfml_expr_contains(ctx, left, right);
    case CFML_OP_NOT_CONTAINS:
        return cfml_expr_not_contains(ctx, left, right);
    case CFML_OP_BITAND:
        return cfml_expr_bitand(ctx, left, right);
    case CFML_OP_BITOR:
        return cfml_expr_bitor(ctx, left, right);
    case CFML_OP_BITXOR:
        return cfml_expr_bitxor(ctx, left, right);
    default:
        return cfml_create_null(ctx->pool);
    }
}

/* Evaluate unary expression */
cfml_value_t *
cfml_eval_unary(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *operand;

    operand = cfml_eval_expression(ctx, node->data.unary.operand);
    if (operand == NULL) {
        return NULL;
    }

    switch (node->data.unary.op) {
    case CFML_OP_NOT:
        return cfml_expr_not(ctx, operand);
    case CFML_OP_NEG:
        return cfml_expr_neg(ctx, operand);
    case CFML_OP_POS:
        return cfml_expr_pos(ctx, operand);
    case CFML_OP_BITNOT:
        return cfml_expr_bitnot(ctx, operand);
    case CFML_OP_PRE_INC:
    case CFML_OP_POST_INC:
        {
            cfml_value_t *result = cfml_expr_add(ctx, operand, 
                cfml_create_integer(ctx->pool, 1));
            /* Update the variable */
            if (node->data.unary.operand->type == CFML_AST_EXPR_VARIABLE) {
                cfml_set_variable(ctx, &node->data.unary.operand->data.variable.name, result);
            }
            return (node->data.unary.op == CFML_OP_PRE_INC) ? result : operand;
        }
    case CFML_OP_PRE_DEC:
    case CFML_OP_POST_DEC:
        {
            cfml_value_t *result = cfml_expr_subtract(ctx, operand,
                cfml_create_integer(ctx->pool, 1));
            if (node->data.unary.operand->type == CFML_AST_EXPR_VARIABLE) {
                cfml_set_variable(ctx, &node->data.unary.operand->data.variable.name, result);
            }
            return (node->data.unary.op == CFML_OP_PRE_DEC) ? result : operand;
        }
    default:
        return operand;
    }
}

/* Evaluate ternary expression */
cfml_value_t *
cfml_eval_ternary(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *condition;

    condition = cfml_eval_expression(ctx, node->data.ternary.condition);
    if (condition == NULL) {
        return NULL;
    }

    if (cfml_value_to_boolean(condition)) {
        return cfml_eval_expression(ctx, node->data.ternary.true_branch);
    } else {
        return cfml_eval_expression(ctx, node->data.ternary.false_branch);
    }
}

/* Evaluate function call */
cfml_value_t *
cfml_eval_function_call(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_array_t *args;
    cfml_ast_node_t **arg_nodes;
    cfml_value_t **arg_slot;
    ngx_uint_t i;

    /* Evaluate arguments */
    args = ngx_array_create(ctx->pool, node->data.function_call.args->nelts,
                            sizeof(cfml_value_t *));
    if (args == NULL) {
        return NULL;
    }

    arg_nodes = node->data.function_call.args->elts;
    for (i = 0; i < node->data.function_call.args->nelts; i++) {
        arg_slot = ngx_array_push(args);
        if (arg_slot == NULL) {
            return NULL;
        }
        *arg_slot = cfml_eval_expression(ctx, arg_nodes[i]);
        if (*arg_slot == NULL) {
            return NULL;
        }
    }

    /* Check for built-in function */
    if (cfml_is_builtin_function(&node->data.function_call.name)) {
        return cfml_call_builtin(ctx, &node->data.function_call.name, args);
    }

    /* Check for user-defined function */
    cfml_value_t *func_var = cfml_get_variable(ctx, &node->data.function_call.name);
    if (func_var != NULL && func_var->type == CFML_TYPE_FUNCTION) {
        return cfml_function_call(ctx, func_var->data.function, args);
    }

    /* Function not found */
    ctx->error_message.data = (u_char *)"Function not found";
    ctx->error_message.len = 18;
    return NULL;
}

/* Evaluate method call */
cfml_value_t *
cfml_eval_method_call(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *object;
    ngx_array_t *args;
    cfml_ast_node_t **arg_nodes;
    cfml_value_t **arg_slot;
    ngx_uint_t i;

    /* Evaluate object */
    object = cfml_eval_expression(ctx, node->data.method_call.object);
    if (object == NULL) {
        return NULL;
    }

    /* Evaluate arguments */
    args = ngx_array_create(ctx->pool, node->data.method_call.args->nelts,
                            sizeof(cfml_value_t *));
    if (args == NULL) {
        return NULL;
    }

    arg_nodes = node->data.method_call.args->elts;
    for (i = 0; i < node->data.method_call.args->nelts; i++) {
        arg_slot = ngx_array_push(args);
        if (arg_slot == NULL) {
            return NULL;
        }
        *arg_slot = cfml_eval_expression(ctx, arg_nodes[i]);
        if (*arg_slot == NULL) {
            return NULL;
        }
    }

    /* Handle different object types */
    switch (object->type) {
    case CFML_TYPE_COMPONENT:
        return cfml_component_invoke(ctx, object->data.component,
                                     &node->data.method_call.method_name, args);

    case CFML_TYPE_ARRAY:
        /* Array member methods */
        /* TODO: Implement array.append(), etc. */
        break;

    case CFML_TYPE_STRUCT:
        /* Struct member methods */
        /* TODO: Implement struct.keyExists(), etc. */
        break;

    case CFML_TYPE_QUERY:
        /* Query member methods */
        break;

    case CFML_TYPE_STRING:
        /* String member methods */
        /* TODO: Implement string.len(), etc. */
        break;

    default:
        break;
    }

    ctx->error_message.data = (u_char *)"Method not found";
    ctx->error_message.len = 16;
    return NULL;
}

/* Evaluate variable reference */
cfml_value_t *
cfml_eval_variable(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    return cfml_get_variable(ctx, &node->data.variable.name);
}

/* Evaluate array access */
cfml_value_t *
cfml_eval_array_access(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *base, *index;

    base = cfml_eval_expression(ctx, node->data.access.base);
    if (base == NULL) {
        return NULL;
    }

    index = cfml_eval_expression(ctx, node->data.access.index);
    if (index == NULL) {
        return NULL;
    }

    if (base->type == CFML_TYPE_ARRAY) {
        int64_t idx;
        if (cfml_value_to_integer(index, &idx) != NGX_OK) {
            return NULL;
        }
        /* CFML arrays are 1-indexed */
        return cfml_array_get(base->data.array, idx - 1);
    } else if (base->type == CFML_TYPE_STRUCT) {
        ngx_str_t key;
        if (cfml_value_to_string(ctx, index, &key) != NGX_OK) {
            return NULL;
        }
        return cfml_struct_get(base->data.structure, &key);
    } else if (base->type == CFML_TYPE_QUERY) {
        /* Query column access */
        ngx_str_t col;
        if (cfml_value_to_string(ctx, index, &col) != NGX_OK) {
            return NULL;
        }
        return cfml_query_get_cell(base->data.query, &col, 
                                   base->data.query->current_row);
    }

    return cfml_create_null(ctx->pool);
}

/* Evaluate struct/property access */
cfml_value_t *
cfml_eval_struct_access(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *base, *key;

    base = cfml_eval_expression(ctx, node->data.access.base);
    if (base == NULL) {
        return NULL;
    }

    key = cfml_eval_expression(ctx, node->data.access.index);
    if (key == NULL) {
        return NULL;
    }

    if (base->type == CFML_TYPE_STRUCT) {
        ngx_str_t key_str;
        if (cfml_value_to_string(ctx, key, &key_str) != NGX_OK) {
            return NULL;
        }
        return cfml_struct_get(base->data.structure, &key_str);
    } else if (base->type == CFML_TYPE_COMPONENT) {
        ngx_str_t key_str;
        if (cfml_value_to_string(ctx, key, &key_str) != NGX_OK) {
            return NULL;
        }
        return cfml_component_get_property(base->data.component, &key_str);
    }

    return cfml_create_null(ctx->pool);
}

/* Evaluate assignment */
cfml_value_t *
cfml_eval_assignment(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *value;
    cfml_ast_node_t *target = node->data.assignment.target;

    value = cfml_eval_expression(ctx, node->data.assignment.value);
    if (value == NULL) {
        return NULL;
    }

    /* Handle compound assignment */
    if (node->type == CFML_AST_EXPR_COMPOUND_ASSIGNMENT) {
        cfml_value_t *current = cfml_eval_expression(ctx, target);
        if (current == NULL) {
            return NULL;
        }

        switch (node->data.assignment.compound_op) {
        case CFML_OP_ADD:
            value = cfml_expr_add(ctx, current, value);
            break;
        case CFML_OP_SUB:
            value = cfml_expr_subtract(ctx, current, value);
            break;
        case CFML_OP_MUL:
            value = cfml_expr_multiply(ctx, current, value);
            break;
        case CFML_OP_DIV:
            value = cfml_expr_divide(ctx, current, value);
            break;
        case CFML_OP_MOD:
            value = cfml_expr_modulo(ctx, current, value);
            break;
        case CFML_OP_CONCAT:
            value = cfml_expr_concat(ctx, current, value);
            break;
        default:
            break;
        }
    }

    /* Assign to target */
    if (target->type == CFML_AST_EXPR_VARIABLE) {
        cfml_set_variable(ctx, &target->data.variable.name, value);
    } else if (target->type == CFML_AST_EXPR_ARRAY_ACCESS) {
        cfml_value_t *base = cfml_eval_expression(ctx, target->data.access.base);
        cfml_value_t *index = cfml_eval_expression(ctx, target->data.access.index);
        
        if (base->type == CFML_TYPE_ARRAY) {
            int64_t idx;
            cfml_value_to_integer(index, &idx);
            cfml_array_set(base->data.array, idx - 1, value);
        } else if (base->type == CFML_TYPE_STRUCT) {
            ngx_str_t key;
            cfml_value_to_string(ctx, index, &key);
            cfml_struct_set(base->data.structure, &key, value);
        }
    } else if (target->type == CFML_AST_EXPR_STRUCT_ACCESS) {
        cfml_value_t *base = cfml_eval_expression(ctx, target->data.access.base);
        cfml_value_t *key = cfml_eval_expression(ctx, target->data.access.index);
        
        if (base->type == CFML_TYPE_STRUCT) {
            ngx_str_t key_str;
            cfml_value_to_string(ctx, key, &key_str);
            cfml_struct_set(base->data.structure, &key_str, value);
        } else if (base->type == CFML_TYPE_COMPONENT) {
            ngx_str_t key_str;
            cfml_value_to_string(ctx, key, &key_str);
            cfml_component_set_property(base->data.component, &key_str, value);
        }
    }

    return value;
}

/* Output a value */
ngx_int_t
cfml_output_value(cfml_context_t *ctx, cfml_value_t *value)
{
    ngx_str_t str;

    if (value == NULL || value->is_null) {
        return NGX_OK;
    }

    if (cfml_value_to_string(ctx, value, &str) != NGX_OK) {
        return NGX_ERROR;
    }

    return cfml_output_string(ctx, &str);
}

/* Output a string */
ngx_int_t
cfml_output_string(cfml_context_t *ctx, ngx_str_t *str)
{
    return cfml_output_text(ctx, str->data, str->len);
}

/* Output raw text */
ngx_int_t
cfml_output_text(cfml_context_t *ctx, u_char *text, size_t len)
{
    ngx_chain_t *cl;
    ngx_buf_t *b;

    if (len == 0) {
        return NGX_OK;
    }

    /* Check for savecontent */
    if (ctx->savecontent_stack->nelts > 0) {
        /* TODO: Redirect to savecontent buffer */
    }

    b = ngx_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_copy(b->pos, text, len);
    b->memory = 1;

    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    *ctx->output_last = cl;
    ctx->output_last = &cl->next;
    ctx->output_size += len;

    return NGX_OK;
}

/* Interpolate string (handle #variable# expressions) */
ngx_int_t
cfml_interpolate_string(cfml_context_t *ctx, ngx_str_t *input, ngx_str_t *output)
{
    u_char *p, *end, *start, *out;
    size_t out_len;
    ngx_int_t in_expr;

    /* First pass: calculate output length */
    out_len = 0;
    p = input->data;
    end = input->data + input->len;
    in_expr = 0;

    while (p < end) {
        if (*p == '#') {
            if (p + 1 < end && *(p + 1) == '#') {
                /* Escaped hash */
                out_len++;
                p += 2;
            } else if (!in_expr) {
                /* Start of expression */
                in_expr = 1;
                start = p + 1;
                p++;
            } else {
                /* End of expression */
                ngx_str_t expr_str;
                expr_str.data = start;
                expr_str.len = p - start;
                
                /* Parse and evaluate expression */
                cfml_template_t *expr_tmpl = cfml_parse_string(ctx->pool, &expr_str);
                if (expr_tmpl != NULL && expr_tmpl->root != NULL) {
                    /* Estimate space for result */
                    out_len += 256;  /* Rough estimate */
                }
                
                in_expr = 0;
                p++;
            }
        } else {
            if (!in_expr) {
                out_len++;
            }
            p++;
        }
    }

    /* Allocate output buffer */
    output->data = ngx_pnalloc(ctx->pool, out_len + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }

    /* Second pass: build output */
    out = output->data;
    p = input->data;
    in_expr = 0;

    while (p < end) {
        if (*p == '#') {
            if (p + 1 < end && *(p + 1) == '#') {
                *out++ = '#';
                p += 2;
            } else if (!in_expr) {
                in_expr = 1;
                start = p + 1;
                p++;
            } else {
                ngx_str_t expr_str, result_str;
                expr_str.data = start;
                expr_str.len = p - start;
                
                /* This is a simplified version - full implementation would
                   parse the expression and evaluate it */
                cfml_value_t *var = cfml_get_variable(ctx, &expr_str);
                if (var != NULL) {
                    cfml_value_to_string(ctx, var, &result_str);
                    out = ngx_copy(out, result_str.data, result_str.len);
                }
                
                in_expr = 0;
                p++;
            }
        } else {
            if (!in_expr) {
                *out++ = *p;
            }
            p++;
        }
    }

    output->len = out - output->data;
    *out = '\0';

    return NGX_OK;
}

/* Convert value to boolean */
ngx_int_t
cfml_value_to_boolean(cfml_value_t *value)
{
    if (value == NULL || value->is_null) {
        return 0;
    }

    switch (value->type) {
    case CFML_TYPE_BOOLEAN:
        return value->data.boolean;

    case CFML_TYPE_INTEGER:
        return value->data.integer != 0;

    case CFML_TYPE_FLOAT:
        return value->data.floating != 0.0;

    case CFML_TYPE_STRING:
        if (value->data.string.len == 0) {
            return 0;
        }
        /* Check for "true", "yes", "1" */
        if (ngx_strncasecmp(value->data.string.data, (u_char *)"true", 4) == 0 ||
            ngx_strncasecmp(value->data.string.data, (u_char *)"yes", 3) == 0 ||
            (value->data.string.len == 1 && value->data.string.data[0] == '1')) {
            return 1;
        }
        /* Check for "false", "no", "0" */
        if (ngx_strncasecmp(value->data.string.data, (u_char *)"false", 5) == 0 ||
            ngx_strncasecmp(value->data.string.data, (u_char *)"no", 2) == 0 ||
            (value->data.string.len == 1 && value->data.string.data[0] == '0')) {
            return 0;
        }
        /* Non-empty string is true */
        return 1;

    case CFML_TYPE_ARRAY:
        return value->data.array && cfml_array_len(value->data.array) > 0;

    case CFML_TYPE_STRUCT:
        return value->data.structure && cfml_struct_count(value->data.structure) > 0;

    case CFML_TYPE_QUERY:
        return value->data.query && cfml_query_row_count(value->data.query) > 0;

    default:
        return 0;
    }
}

/* Convert value to integer */
ngx_int_t
cfml_value_to_integer(cfml_value_t *value, int64_t *result)
{
    if (value == NULL || value->is_null) {
        *result = 0;
        return NGX_OK;
    }

    switch (value->type) {
    case CFML_TYPE_INTEGER:
        *result = value->data.integer;
        return NGX_OK;

    case CFML_TYPE_FLOAT:
        *result = (int64_t)value->data.floating;
        return NGX_OK;

    case CFML_TYPE_BOOLEAN:
        *result = value->data.boolean ? 1 : 0;
        return NGX_OK;

    case CFML_TYPE_STRING:
        *result = ngx_atoi(value->data.string.data, value->data.string.len);
        return NGX_OK;

    default:
        *result = 0;
        return NGX_ERROR;
    }
}

/* Convert value to float */
ngx_int_t
cfml_value_to_float(cfml_value_t *value, double *result)
{
    if (value == NULL || value->is_null) {
        *result = 0.0;
        return NGX_OK;
    }

    switch (value->type) {
    case CFML_TYPE_FLOAT:
        *result = value->data.floating;
        return NGX_OK;

    case CFML_TYPE_INTEGER:
        *result = (double)value->data.integer;
        return NGX_OK;

    case CFML_TYPE_BOOLEAN:
        *result = value->data.boolean ? 1.0 : 0.0;
        return NGX_OK;

    case CFML_TYPE_STRING:
        *result = ngx_atofp(value->data.string.data, value->data.string.len, 10);
        return NGX_OK;

    default:
        *result = 0.0;
        return NGX_ERROR;
    }
}

/* Convert value to string */
ngx_int_t
cfml_value_to_string(cfml_context_t *ctx, cfml_value_t *value, ngx_str_t *result)
{
    u_char *p;

    if (value == NULL || value->is_null) {
        result->data = (u_char *)"";
        result->len = 0;
        return NGX_OK;
    }

    switch (value->type) {
    case CFML_TYPE_STRING:
        *result = value->data.string;
        return NGX_OK;

    case CFML_TYPE_INTEGER:
        result->data = ngx_pnalloc(ctx->pool, NGX_INT64_LEN + 1);
        if (result->data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_sprintf(result->data, "%L", value->data.integer);
        result->len = p - result->data;
        return NGX_OK;

    case CFML_TYPE_FLOAT:
        result->data = ngx_pnalloc(ctx->pool, 64);
        if (result->data == NULL) {
            return NGX_ERROR;
        }
        result->len = ngx_sprintf(result->data, "%.10g", value->data.floating) 
                      - result->data;
        return NGX_OK;

    case CFML_TYPE_BOOLEAN:
        if (value->data.boolean) {
            ngx_str_set(result, "true");
        } else {
            ngx_str_set(result, "false");
        }
        return NGX_OK;

    case CFML_TYPE_DATE:
        result->data = ngx_pnalloc(ctx->pool, 64);
        if (result->data == NULL) {
            return NGX_ERROR;
        }
        /* Format as YYYY-MM-DD HH:MM:SS */
        {
            struct tm *tm = localtime(&value->data.date.time);
            result->len = strftime((char *)result->data, 64, 
                                   "%Y-%m-%d %H:%M:%S", tm);
        }
        return NGX_OK;

    case CFML_TYPE_ARRAY:
        /* Convert array to string representation */
        ngx_str_set(result, "[Array]");
        return NGX_OK;

    case CFML_TYPE_STRUCT:
        ngx_str_set(result, "[Struct]");
        return NGX_OK;

    case CFML_TYPE_QUERY:
        ngx_str_set(result, "[Query]");
        return NGX_OK;

    case CFML_TYPE_COMPONENT:
        ngx_str_set(result, "[Component]");
        return NGX_OK;

    default:
        result->data = (u_char *)"";
        result->len = 0;
        return NGX_OK;
    }
}

/* Include template */
ngx_int_t
cfml_include_template(cfml_context_t *ctx, ngx_str_t *path)
{
    cfml_template_t *tmpl;
    ngx_str_t full_path;
    u_char *p;

    /* Check include depth */
    if (ctx->include_depth >= ctx->max_include_depth) {
        ngx_str_set(&ctx->error_message, "Maximum include depth exceeded");
        return NGX_ERROR;
    }

    /* Resolve path relative to current template */
    if (path->data[0] != '/') {
        /* Relative path - find last slash */
        size_t dir_len = 0;
        u_char *slash = NULL;
        u_char *scan;
        for (scan = ctx->current_template->path.data + ctx->current_template->path.len - 1;
             scan >= ctx->current_template->path.data; scan--) {
            if (*scan == '/') {
                slash = scan;
                break;
            }
        }
        if (slash) {
            dir_len = slash - ctx->current_template->path.data + 1;
        }
        
        full_path.len = dir_len + path->len;
        full_path.data = ngx_pnalloc(ctx->pool, full_path.len + 1);
        if (full_path.data == NULL) {
            return NGX_ERROR;
        }
        
        p = ngx_copy(full_path.data, ctx->current_template->path.data, dir_len);
        p = ngx_copy(p, path->data, path->len);
        *p = '\0';
    } else {
        full_path = *path;
    }

    /* Parse and execute included template */
    tmpl = cfml_parse_template(ctx->pool, &full_path, 1);
    if (tmpl == NULL) {
        return NGX_ERROR;
    }

    ctx->include_depth++;
    
    cfml_template_t *saved_template = ctx->current_template;
    ctx->current_template = tmpl;
    
    ngx_int_t rc = cfml_execute(ctx, tmpl->root);
    
    ctx->current_template = saved_template;
    ctx->include_depth--;

    return rc;
}

/* Load Application.cfc */
ngx_int_t
cfml_load_application_cfc(cfml_context_t *ctx, ngx_str_t *page_path)
{
    ngx_str_t app_path;
    u_char *p, *dir_end;
    cfml_component_t *app;

    /* Search for Application.cfc in current directory and parents */
    /* Find last slash */
    dir_end = NULL;
    for (p = page_path->data + page_path->len - 1; p >= page_path->data; p--) {
        if (*p == '/') {
            dir_end = p;
            break;
        }
    }
    if (dir_end == NULL) {
        return NGX_DECLINED;
    }

    while (dir_end >= page_path->data) {
        app_path.len = (dir_end - page_path->data) + sizeof("/Application.cfc");
        app_path.data = ngx_pnalloc(ctx->pool, app_path.len);
        if (app_path.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_copy(app_path.data, page_path->data, dir_end - page_path->data + 1);
        p = ngx_cpymem(p, "Application.cfc", sizeof("Application.cfc") - 1);
        *p = '\0';
        app_path.len = p - app_path.data;

        /* Check if file exists */
        ngx_file_info_t fi;
        if (ngx_file_info(app_path.data, &fi) != NGX_FILE_ERROR) {
            app = cfml_component_load(ctx, &app_path);
            if (app != NULL) {
                ctx->application_cfc = app;
                
                /* Initialize application */
                cfml_invoke_application_method(ctx, "onApplicationStart", NULL);
                cfml_invoke_application_method(ctx, "onSessionStart", NULL);
                
                return NGX_OK;
            }
        }

        /* Move to parent directory */
        dir_end--;
        while (dir_end >= page_path->data && *dir_end != '/') {
            dir_end--;
        }
    }

    return NGX_DECLINED;
}

/* Invoke Application.cfc method */
ngx_int_t
cfml_invoke_application_method(cfml_context_t *ctx, const char *method,
                               ngx_str_t *arg)
{
    ngx_str_t method_name;
    ngx_array_t *args;

    if (ctx->application_cfc == NULL) {
        return NGX_DECLINED;
    }

    method_name.data = (u_char *)method;
    method_name.len = ngx_strlen(method);

    if (!cfml_component_has_function(ctx->application_cfc, &method_name)) {
        return NGX_DECLINED;
    }

    args = ngx_array_create(ctx->pool, 1, sizeof(cfml_value_t *));
    if (args == NULL) {
        return NGX_ERROR;
    }

    if (arg != NULL) {
        cfml_value_t **slot = ngx_array_push(args);
        *slot = cfml_create_string(ctx->pool, arg);
    }

    cfml_value_t *result = cfml_component_invoke(ctx, ctx->application_cfc,
                                                  &method_name, args);
    
    if (result == NULL && ctx->exception != NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Throw exception */
ngx_int_t
cfml_throw_exception(cfml_context_t *ctx, ngx_str_t *type, ngx_str_t *message)
{
    cfml_value_t *exc;

    exc = cfml_create_struct(ctx->pool);
    if (exc == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t type_key = ngx_string("type");
    ngx_str_t message_key = ngx_string("message");
    
    cfml_struct_set(exc->data.structure, &type_key, 
                    cfml_create_string(ctx->pool, type));
    cfml_struct_set(exc->data.structure, &message_key,
                    cfml_create_string(ctx->pool, message));

    ctx->exception = exc;

    return NGX_OK;
}

/* Clear exception */
void
cfml_clear_exception(cfml_context_t *ctx)
{
    ctx->exception = NULL;
}
