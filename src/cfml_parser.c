/*
 * CFML Parser - Parse CFML source into AST
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_parser.h"
#include "cfml_lexer.h"
#include "cfml_cache.h"
#include <stdarg.h>

/* Forward declarations */
static ngx_int_t cfml_parse_template_content(cfml_parser_t *parser, 
                                              cfml_ast_node_t *parent);
static ngx_int_t cfml_parse_tag_content(cfml_parser_t *parser, 
                                         cfml_ast_node_t *parent,
                                         ngx_str_t *end_tag);

/* Create parser */
cfml_parser_t *
cfml_parser_create(ngx_pool_t *pool, u_char *input, size_t len)
{
    cfml_parser_t *parser;

    parser = ngx_pcalloc(pool, sizeof(cfml_parser_t));
    if (parser == NULL) {
        return NULL;
    }

    parser->pool = pool;
    parser->lexer = cfml_lexer_create(pool, input, len);
    if (parser->lexer == NULL) {
        return NULL;
    }

    parser->template = ngx_pcalloc(pool, sizeof(cfml_template_t));
    if (parser->template == NULL) {
        return NULL;
    }

    parser->template->pool = pool;

    return parser;
}

/* Destroy parser */
void
cfml_parser_destroy(cfml_parser_t *parser)
{
    if (parser && parser->lexer) {
        cfml_lexer_destroy(parser->lexer);
    }
}

/* Create AST node */
cfml_ast_node_t *
cfml_ast_create_node(ngx_pool_t *pool, cfml_ast_type_t type)
{
    cfml_ast_node_t *node;

    node = ngx_pcalloc(pool, sizeof(cfml_ast_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->type = type;
    node->pool = pool;

    node->attributes = ngx_array_create(pool, 8, sizeof(cfml_ast_attr_t));
    if (node->attributes == NULL) {
        return NULL;
    }

    node->children = ngx_array_create(pool, 16, sizeof(cfml_ast_node_t *));
    if (node->children == NULL) {
        return NULL;
    }

    return node;
}

/* Add child to node */
void
cfml_ast_add_child(cfml_ast_node_t *parent, cfml_ast_node_t *child)
{
    cfml_ast_node_t **slot;

    if (parent == NULL || child == NULL) {
        return;
    }

    slot = ngx_array_push(parent->children);
    if (slot != NULL) {
        *slot = child;
    }
}

/* Set attribute on node */
void
cfml_ast_set_attribute(cfml_ast_node_t *node, ngx_str_t *name, 
                       cfml_ast_node_t *value)
{
    cfml_ast_attr_t *attr;

    if (node == NULL || name == NULL) {
        return;
    }

    attr = ngx_array_push(node->attributes);
    if (attr != NULL) {
        attr->name = *name;
        attr->value = value;
    }
}

/* Get attribute from node */
cfml_ast_node_t *
cfml_ast_get_attribute(cfml_ast_node_t *node, ngx_str_t *name)
{
    cfml_ast_attr_t *attrs;
    ngx_uint_t i;

    if (node == NULL || name == NULL) {
        return NULL;
    }

    attrs = node->attributes->elts;
    for (i = 0; i < node->attributes->nelts; i++) {
        if (attrs[i].name.len == name->len &&
            ngx_strncasecmp(attrs[i].name.data, name->data, name->len) == 0) {
            return attrs[i].value;
        }
    }

    return NULL;
}

/* Parser error */
void
cfml_parser_error(cfml_parser_t *parser, const char *fmt, ...)
{
    va_list args;
    u_char *p;
    size_t len;

    parser->error_line = parser->lexer->line;
    parser->error_column = parser->lexer->column;

    parser->error_message.data = ngx_pnalloc(parser->pool, 512);
    if (parser->error_message.data == NULL) {
        return;
    }

    va_start(args, fmt);
    p = ngx_vslprintf(parser->error_message.data, 
                      parser->error_message.data + 511,
                      fmt, args);
    va_end(args);

    len = p - parser->error_message.data;
    parser->error_message.len = len;
}

/* Consume token if it matches expected type */
static ngx_int_t
cfml_parser_expect(cfml_parser_t *parser, cfml_token_type_t type)
{
    cfml_token_t *token = cfml_lexer_next_token(parser->lexer);
    
    if (token == NULL || token->type != type) {
        cfml_parser_error(parser, "Expected %s, got %s",
                          cfml_token_type_name(type),
                          token ? cfml_token_type_name(token->type) : "NULL");
        return NGX_ERROR;
    }

    parser->current_token = token;
    return NGX_OK;
}

/* Parse expression - main entry point */
cfml_ast_node_t *
cfml_parse_expression(cfml_parser_t *parser)
{
    cfml_ast_node_t *node = NULL;
    
    if (cfml_parse_assignment_expr(parser, &node) != NGX_OK) {
        return NULL;
    }
    
    return node;
}

/* Parse assignment expression */
ngx_int_t
cfml_parse_assignment_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_ternary_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    token = cfml_lexer_peek_token(parser->lexer);
    
    if (token->type == CFML_TOKEN_ASSIGN ||
        token->type == CFML_TOKEN_PLUS_ASSIGN ||
        token->type == CFML_TOKEN_MINUS_ASSIGN ||
        token->type == CFML_TOKEN_MUL_ASSIGN ||
        token->type == CFML_TOKEN_DIV_ASSIGN ||
        token->type == CFML_TOKEN_MOD_ASSIGN ||
        token->type == CFML_TOKEN_CONCAT_ASSIGN) {
        
        cfml_ast_node_t *assign_node;
        cfml_ast_node_t *right;
        
        cfml_lexer_next_token(parser->lexer);  /* Consume operator */
        
        assign_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_ASSIGNMENT);
        if (assign_node == NULL) {
            return NGX_ERROR;
        }
        
        assign_node->data.assignment.target = left;
        
        if (token->type != CFML_TOKEN_ASSIGN) {
            /* Compound assignment */
            assign_node->type = CFML_AST_EXPR_COMPOUND_ASSIGNMENT;
            switch (token->type) {
            case CFML_TOKEN_PLUS_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_ADD;
                break;
            case CFML_TOKEN_MINUS_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_SUB;
                break;
            case CFML_TOKEN_MUL_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_MUL;
                break;
            case CFML_TOKEN_DIV_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_DIV;
                break;
            case CFML_TOKEN_MOD_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_MOD;
                break;
            case CFML_TOKEN_CONCAT_ASSIGN:
                assign_node->data.assignment.compound_op = CFML_OP_CONCAT;
                break;
            default:
                break;
            }
        }
        
        if (cfml_parse_assignment_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        assign_node->data.assignment.value = right;
        *node = assign_node;
        return NGX_OK;
    }

    *node = left;
    return NGX_OK;
}

/* Parse ternary expression */
ngx_int_t
cfml_parse_ternary_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *condition;
    cfml_token_t *token;

    if (cfml_parse_or_expr(parser, &condition) != NGX_OK) {
        return NGX_ERROR;
    }

    token = cfml_lexer_peek_token(parser->lexer);
    
    if (token->type == CFML_TOKEN_QUESTION) {
        cfml_ast_node_t *ternary_node;
        cfml_ast_node_t *true_expr, *false_expr;
        
        cfml_lexer_next_token(parser->lexer);  /* Consume ? */
        
        ternary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_TERNARY);
        if (ternary_node == NULL) {
            return NGX_ERROR;
        }
        
        if (cfml_parse_assignment_expr(parser, &true_expr) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (cfml_parser_expect(parser, CFML_TOKEN_COLON) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (cfml_parse_ternary_expr(parser, &false_expr) != NGX_OK) {
            return NGX_ERROR;
        }
        
        ternary_node->data.ternary.condition = condition;
        ternary_node->data.ternary.true_branch = true_expr;
        ternary_node->data.ternary.false_branch = false_expr;
        
        *node = ternary_node;
        return NGX_OK;
    }
    
    /* Elvis operator ?: */
    if (token->type == CFML_TOKEN_ELVIS) {
        cfml_ast_node_t *ternary_node;
        cfml_ast_node_t *false_expr;
        
        cfml_lexer_next_token(parser->lexer);  /* Consume ?: */
        
        ternary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_TERNARY);
        if (ternary_node == NULL) {
            return NGX_ERROR;
        }
        
        if (cfml_parse_ternary_expr(parser, &false_expr) != NGX_OK) {
            return NGX_ERROR;
        }
        
        ternary_node->data.ternary.condition = condition;
        ternary_node->data.ternary.true_branch = condition;  /* Same as condition */
        ternary_node->data.ternary.false_branch = false_expr;
        
        *node = ternary_node;
        return NGX_OK;
    }

    *node = condition;
    return NGX_OK;
}

/* Parse OR expression */
ngx_int_t
cfml_parse_or_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_and_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_OR && 
            token->type != CFML_TOKEN_XOR &&
            token->type != CFML_TOKEN_EQV &&
            token->type != CFML_TOKEN_IMP) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_OR:
            binary_node->data.binary.op = CFML_OP_OR;
            break;
        case CFML_TOKEN_XOR:
            binary_node->data.binary.op = CFML_OP_XOR;
            break;
        case CFML_TOKEN_EQV:
            binary_node->data.binary.op = CFML_OP_EQV;
            break;
        case CFML_TOKEN_IMP:
            binary_node->data.binary.op = CFML_OP_IMP;
            break;
        default:
            break;
        }
        
        if (cfml_parse_and_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse AND expression */
ngx_int_t
cfml_parse_and_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_equality_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_AND) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.op = CFML_OP_AND;
        
        if (cfml_parse_equality_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse equality expression */
ngx_int_t
cfml_parse_equality_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_relational_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_EQ && 
            token->type != CFML_TOKEN_NEQ &&
            token->type != CFML_TOKEN_CONTAINS &&
            token->type != CFML_TOKEN_NOT_CONTAINS) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_EQ:
            binary_node->data.binary.op = CFML_OP_EQ;
            break;
        case CFML_TOKEN_NEQ:
            binary_node->data.binary.op = CFML_OP_NEQ;
            break;
        case CFML_TOKEN_CONTAINS:
            binary_node->data.binary.op = CFML_OP_CONTAINS;
            break;
        case CFML_TOKEN_NOT_CONTAINS:
            binary_node->data.binary.op = CFML_OP_NOT_CONTAINS;
            break;
        default:
            break;
        }
        
        if (cfml_parse_relational_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse relational expression */
ngx_int_t
cfml_parse_relational_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_additive_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_LT && 
            token->type != CFML_TOKEN_LTE &&
            token->type != CFML_TOKEN_GT &&
            token->type != CFML_TOKEN_GTE) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_LT:
            binary_node->data.binary.op = CFML_OP_LT;
            break;
        case CFML_TOKEN_LTE:
            binary_node->data.binary.op = CFML_OP_LTE;
            break;
        case CFML_TOKEN_GT:
            binary_node->data.binary.op = CFML_OP_GT;
            break;
        case CFML_TOKEN_GTE:
            binary_node->data.binary.op = CFML_OP_GTE;
            break;
        default:
            break;
        }
        
        if (cfml_parse_additive_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse additive expression */
ngx_int_t
cfml_parse_additive_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_multiplicative_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_PLUS && 
            token->type != CFML_TOKEN_MINUS &&
            token->type != CFML_TOKEN_CONCAT) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_PLUS:
            binary_node->data.binary.op = CFML_OP_ADD;
            break;
        case CFML_TOKEN_MINUS:
            binary_node->data.binary.op = CFML_OP_SUB;
            break;
        case CFML_TOKEN_CONCAT:
            binary_node->data.binary.op = CFML_OP_CONCAT;
            break;
        default:
            break;
        }
        
        if (cfml_parse_multiplicative_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse multiplicative expression */
ngx_int_t
cfml_parse_multiplicative_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_unary_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type != CFML_TOKEN_MULTIPLY && 
            token->type != CFML_TOKEN_DIVIDE &&
            token->type != CFML_TOKEN_MOD &&
            token->type != CFML_TOKEN_BACKSLASH &&
            token->type != CFML_TOKEN_POWER) {
            break;
        }
        
        cfml_lexer_next_token(parser->lexer);
        
        cfml_ast_node_t *binary_node;
        cfml_ast_node_t *right;
        
        binary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_BINARY);
        if (binary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_MULTIPLY:
            binary_node->data.binary.op = CFML_OP_MUL;
            break;
        case CFML_TOKEN_DIVIDE:
            binary_node->data.binary.op = CFML_OP_DIV;
            break;
        case CFML_TOKEN_MOD:
            binary_node->data.binary.op = CFML_OP_MOD;
            break;
        case CFML_TOKEN_BACKSLASH:
            binary_node->data.binary.op = CFML_OP_INTDIV;
            break;
        case CFML_TOKEN_POWER:
            binary_node->data.binary.op = CFML_OP_POW;
            break;
        default:
            break;
        }
        
        if (cfml_parse_unary_expr(parser, &right) != NGX_OK) {
            return NGX_ERROR;
        }
        
        binary_node->data.binary.left = left;
        binary_node->data.binary.right = right;
        left = binary_node;
    }

    *node = left;
    return NGX_OK;
}

/* Parse unary expression */
ngx_int_t
cfml_parse_unary_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_token_t *token;
    
    token = cfml_lexer_peek_token(parser->lexer);
    
    if (token->type == CFML_TOKEN_NOT ||
        token->type == CFML_TOKEN_MINUS ||
        token->type == CFML_TOKEN_PLUS ||
        token->type == CFML_TOKEN_INCREMENT ||
        token->type == CFML_TOKEN_DECREMENT) {
        
        cfml_ast_node_t *unary_node;
        cfml_ast_node_t *operand;
        
        cfml_lexer_next_token(parser->lexer);
        
        unary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_UNARY);
        if (unary_node == NULL) {
            return NGX_ERROR;
        }
        
        switch (token->type) {
        case CFML_TOKEN_NOT:
            unary_node->data.unary.op = CFML_OP_NOT;
            break;
        case CFML_TOKEN_MINUS:
            unary_node->data.unary.op = CFML_OP_NEG;
            break;
        case CFML_TOKEN_PLUS:
            unary_node->data.unary.op = CFML_OP_POS;
            break;
        case CFML_TOKEN_INCREMENT:
            unary_node->data.unary.op = CFML_OP_PRE_INC;
            break;
        case CFML_TOKEN_DECREMENT:
            unary_node->data.unary.op = CFML_OP_PRE_DEC;
            break;
        default:
            break;
        }
        
        if (cfml_parse_unary_expr(parser, &operand) != NGX_OK) {
            return NGX_ERROR;
        }
        
        unary_node->data.unary.operand = operand;
        *node = unary_node;
        return NGX_OK;
    }
    
    return cfml_parse_postfix_expr(parser, node);
}

/* Parse postfix expression */
ngx_int_t
cfml_parse_postfix_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *left;
    cfml_token_t *token;

    if (cfml_parse_primary_expr(parser, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type == CFML_TOKEN_DOT || token->type == CFML_TOKEN_SAFENAV) {
            /* Member access */
            cfml_lexer_next_token(parser->lexer);
            
            token = cfml_lexer_next_token(parser->lexer);
            if (token->type != CFML_TOKEN_IDENTIFIER) {
                cfml_parser_error(parser, "Expected identifier after '.'");
                return NGX_ERROR;
            }
            
            /* Check if it's a method call */
            cfml_token_t *peek = cfml_lexer_peek_token(parser->lexer);
            if (peek->type == CFML_TOKEN_LPAREN) {
                /* Method call */
                cfml_ast_node_t *call_node;
                
                call_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_METHOD_CALL);
                if (call_node == NULL) {
                    return NGX_ERROR;
                }
                
                call_node->data.method_call.object = left;
                call_node->data.method_call.method_name = token->value;
                call_node->data.method_call.args = ngx_array_create(parser->pool, 
                                                                    4, sizeof(cfml_ast_node_t *));
                
                cfml_lexer_next_token(parser->lexer);  /* Consume ( */
                
                /* Parse arguments */
                peek = cfml_lexer_peek_token(parser->lexer);
                if (peek->type != CFML_TOKEN_RPAREN) {
                    do {
                        cfml_ast_node_t *arg;
                        cfml_ast_node_t **slot;
                        
                        if (cfml_parse_assignment_expr(parser, &arg) != NGX_OK) {
                            return NGX_ERROR;
                        }
                        
                        slot = ngx_array_push(call_node->data.method_call.args);
                        if (slot == NULL) {
                            return NGX_ERROR;
                        }
                        *slot = arg;
                        
                        peek = cfml_lexer_peek_token(parser->lexer);
                        if (peek->type == CFML_TOKEN_COMMA) {
                            cfml_lexer_next_token(parser->lexer);
                        }
                    } while (peek->type == CFML_TOKEN_COMMA);
                }
                
                if (cfml_parser_expect(parser, CFML_TOKEN_RPAREN) != NGX_OK) {
                    return NGX_ERROR;
                }
                
                left = call_node;
            } else {
                /* Property access */
                cfml_ast_node_t *access_node;
                cfml_ast_node_t *key_node;
                
                access_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_STRUCT_ACCESS);
                if (access_node == NULL) {
                    return NGX_ERROR;
                }
                
                key_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
                if (key_node == NULL) {
                    return NGX_ERROR;
                }
                
                key_node->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
                key_node->data.literal->type = CFML_TYPE_STRING;
                key_node->data.literal->data.string = token->value;
                
                access_node->data.access.base = left;
                access_node->data.access.index = key_node;
                
                left = access_node;
            }
        } else if (token->type == CFML_TOKEN_LBRACKET) {
            /* Array/struct access */
            cfml_ast_node_t *access_node;
            cfml_ast_node_t *index;
            
            cfml_lexer_next_token(parser->lexer);  /* Consume [ */
            
            if (cfml_parse_assignment_expr(parser, &index) != NGX_OK) {
                return NGX_ERROR;
            }
            
            if (cfml_parser_expect(parser, CFML_TOKEN_RBRACKET) != NGX_OK) {
                return NGX_ERROR;
            }
            
            access_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_ARRAY_ACCESS);
            if (access_node == NULL) {
                return NGX_ERROR;
            }
            
            access_node->data.access.base = left;
            access_node->data.access.index = index;
            
            left = access_node;
        } else if (token->type == CFML_TOKEN_LPAREN) {
            /* Function call */
            cfml_ast_node_t *call_node;
            
            call_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_FUNCTION_CALL);
            if (call_node == NULL) {
                return NGX_ERROR;
            }
            
            /* Get function name from left node */
            if (left->type == CFML_AST_EXPR_VARIABLE) {
                call_node->data.function_call.name = left->data.variable.name;
            }
            
            call_node->data.function_call.args = ngx_array_create(parser->pool,
                                                                  4, sizeof(cfml_ast_node_t *));
            
            cfml_lexer_next_token(parser->lexer);  /* Consume ( */
            
            /* Parse arguments */
            token = cfml_lexer_peek_token(parser->lexer);
            if (token->type != CFML_TOKEN_RPAREN) {
                do {
                    cfml_ast_node_t *arg;
                    cfml_ast_node_t **slot;
                    
                    if (cfml_parse_assignment_expr(parser, &arg) != NGX_OK) {
                        return NGX_ERROR;
                    }
                    
                    slot = ngx_array_push(call_node->data.function_call.args);
                    if (slot == NULL) {
                        return NGX_ERROR;
                    }
                    *slot = arg;
                    
                    token = cfml_lexer_peek_token(parser->lexer);
                    if (token->type == CFML_TOKEN_COMMA) {
                        cfml_lexer_next_token(parser->lexer);
                    }
                } while (token->type == CFML_TOKEN_COMMA);
            }
            
            if (cfml_parser_expect(parser, CFML_TOKEN_RPAREN) != NGX_OK) {
                return NGX_ERROR;
            }
            
            left = call_node;
        } else if (token->type == CFML_TOKEN_INCREMENT || 
                   token->type == CFML_TOKEN_DECREMENT) {
            /* Post increment/decrement */
            cfml_ast_node_t *unary_node;
            
            cfml_lexer_next_token(parser->lexer);
            
            unary_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_INCREMENT);
            if (unary_node == NULL) {
                return NGX_ERROR;
            }
            
            unary_node->data.unary.op = (token->type == CFML_TOKEN_INCREMENT) 
                                        ? CFML_OP_POST_INC : CFML_OP_POST_DEC;
            unary_node->data.unary.operand = left;
            
            left = unary_node;
        } else {
            break;
        }
    }

    *node = left;
    return NGX_OK;
}

/* Parse primary expression */
ngx_int_t
cfml_parse_primary_expr(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_token_t *token;
    cfml_ast_node_t *expr_node;

    token = cfml_lexer_next_token(parser->lexer);

    switch (token->type) {
    case CFML_TOKEN_INTEGER:
    case CFML_TOKEN_FLOAT:
    case CFML_TOKEN_NUMBER:
        expr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
        if (expr_node == NULL) {
            return NGX_ERROR;
        }
        
        expr_node->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (token->type == CFML_TOKEN_FLOAT) {
            expr_node->data.literal->type = CFML_TYPE_FLOAT;
            expr_node->data.literal->data.floating = ngx_atofp(token->value.data, 
                                                               token->value.len, 10);
        } else {
            expr_node->data.literal->type = CFML_TYPE_INTEGER;
            expr_node->data.literal->data.integer = ngx_atoi(token->value.data,
                                                             token->value.len);
        }
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_STRING:
        expr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
        if (expr_node == NULL) {
            return NGX_ERROR;
        }
        
        expr_node->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        expr_node->data.literal->type = CFML_TYPE_STRING;
        expr_node->data.literal->data.string = token->value;
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_BOOLEAN_TRUE:
    case CFML_TOKEN_BOOLEAN_FALSE:
        expr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
        if (expr_node == NULL) {
            return NGX_ERROR;
        }
        
        expr_node->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        expr_node->data.literal->type = CFML_TYPE_BOOLEAN;
        expr_node->data.literal->data.boolean = (token->type == CFML_TOKEN_BOOLEAN_TRUE);
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_NULL:
        expr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
        if (expr_node == NULL) {
            return NGX_ERROR;
        }
        
        expr_node->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        expr_node->data.literal->type = CFML_TYPE_NULL;
        expr_node->data.literal->is_null = 1;
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_IDENTIFIER:
        expr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_VARIABLE);
        if (expr_node == NULL) {
            return NGX_ERROR;
        }
        
        expr_node->data.variable.name = token->value;
        
        /* Check for scope prefix (e.g., variables.foo) */
        cfml_scope_type_t scope;
        if (cfml_is_scope_name(&token->value, &scope)) {
            cfml_token_t *peek = cfml_lexer_peek_token(parser->lexer);
            if (peek->type == CFML_TOKEN_DOT) {
                expr_node->data.variable.scope = scope;
            }
        }
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_LPAREN:
        /* Grouped expression */
        if (cfml_parse_assignment_expr(parser, &expr_node) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (cfml_parser_expect(parser, CFML_TOKEN_RPAREN) != NGX_OK) {
            return NGX_ERROR;
        }
        
        *node = expr_node;
        return NGX_OK;

    case CFML_TOKEN_LBRACKET:
        /* Array literal */
        return cfml_parse_array_literal(parser, node);

    case CFML_TOKEN_LBRACE:
        /* Struct literal */
        return cfml_parse_struct_literal(parser, node);

    case CFML_TOKEN_NEW:
        /* New object */
        {
            cfml_ast_node_t *new_node;
            cfml_token_t *name_token;
            
            new_node = cfml_ast_create_node(parser->pool, CFML_AST_SCRIPT_NEW);
            if (new_node == NULL) {
                return NGX_ERROR;
            }
            
            name_token = cfml_lexer_next_token(parser->lexer);
            if (name_token->type != CFML_TOKEN_IDENTIFIER) {
                cfml_parser_error(parser, "Expected component name after 'new'");
                return NGX_ERROR;
            }
            
            new_node->data.function_call.name = name_token->value;
            new_node->data.function_call.args = ngx_array_create(parser->pool,
                                                                 4, sizeof(cfml_ast_node_t *));
            
            /* Check for constructor arguments */
            cfml_token_t *peek = cfml_lexer_peek_token(parser->lexer);
            if (peek->type == CFML_TOKEN_LPAREN) {
                cfml_lexer_next_token(parser->lexer);  /* Consume ( */
                
                peek = cfml_lexer_peek_token(parser->lexer);
                while (peek->type != CFML_TOKEN_RPAREN && peek->type != CFML_TOKEN_EOF) {
                    cfml_ast_node_t *arg;
                    cfml_ast_node_t **slot;
                    
                    if (cfml_parse_assignment_expr(parser, &arg) != NGX_OK) {
                        return NGX_ERROR;
                    }
                    
                    slot = ngx_array_push(new_node->data.function_call.args);
                    if (slot == NULL) {
                        return NGX_ERROR;
                    }
                    *slot = arg;
                    
                    peek = cfml_lexer_peek_token(parser->lexer);
                    if (peek->type == CFML_TOKEN_COMMA) {
                        cfml_lexer_next_token(parser->lexer);
                        peek = cfml_lexer_peek_token(parser->lexer);
                    }
                }
                
                if (cfml_parser_expect(parser, CFML_TOKEN_RPAREN) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
            
            *node = new_node;
            return NGX_OK;
        }

    default:
        cfml_parser_error(parser, "Unexpected token: %s", 
                          cfml_token_type_name(token->type));
        return NGX_ERROR;
    }
}

/* Parse array literal */
ngx_int_t
cfml_parse_array_literal(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *arr_node;
    cfml_token_t *token;

    arr_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_ARRAY_LITERAL);
    if (arr_node == NULL) {
        return NGX_ERROR;
    }

    token = cfml_lexer_peek_token(parser->lexer);
    while (token->type != CFML_TOKEN_RBRACKET && token->type != CFML_TOKEN_EOF) {
        cfml_ast_node_t *elem;
        
        if (cfml_parse_assignment_expr(parser, &elem) != NGX_OK) {
            return NGX_ERROR;
        }
        
        cfml_ast_add_child(arr_node, elem);
        
        token = cfml_lexer_peek_token(parser->lexer);
        if (token->type == CFML_TOKEN_COMMA) {
            cfml_lexer_next_token(parser->lexer);
            token = cfml_lexer_peek_token(parser->lexer);
        }
    }

    if (cfml_parser_expect(parser, CFML_TOKEN_RBRACKET) != NGX_OK) {
        return NGX_ERROR;
    }

    *node = arr_node;
    return NGX_OK;
}

/* Parse struct literal */
ngx_int_t
cfml_parse_struct_literal(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_ast_node_t *struct_node;
    cfml_token_t *token;

    struct_node = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_STRUCT_LITERAL);
    if (struct_node == NULL) {
        return NGX_ERROR;
    }

    token = cfml_lexer_peek_token(parser->lexer);
    while (token->type != CFML_TOKEN_RBRACE && token->type != CFML_TOKEN_EOF) {
        cfml_ast_node_t *value;
        ngx_str_t key;
        
        /* Key */
        token = cfml_lexer_next_token(parser->lexer);
        if (token->type == CFML_TOKEN_IDENTIFIER || token->type == CFML_TOKEN_STRING) {
            key = token->value;
        } else {
            cfml_parser_error(parser, "Expected struct key");
            return NGX_ERROR;
        }
        
        /* Colon or = */
        token = cfml_lexer_peek_token(parser->lexer);
        if (token->type == CFML_TOKEN_COLON || token->type == CFML_TOKEN_ASSIGN) {
            cfml_lexer_next_token(parser->lexer);
        } else {
            cfml_parser_error(parser, "Expected ':' or '=' after struct key");
            return NGX_ERROR;
        }
        
        /* Value */
        if (cfml_parse_assignment_expr(parser, &value) != NGX_OK) {
            return NGX_ERROR;
        }
        
        cfml_ast_set_attribute(struct_node, &key, value);
        
        token = cfml_lexer_peek_token(parser->lexer);
        if (token->type == CFML_TOKEN_COMMA) {
            cfml_lexer_next_token(parser->lexer);
            token = cfml_lexer_peek_token(parser->lexer);
        }
    }

    if (cfml_parser_expect(parser, CFML_TOKEN_RBRACE) != NGX_OK) {
        return NGX_ERROR;
    }

    *node = struct_node;
    return NGX_OK;
}

/* Parse tag */
ngx_int_t
cfml_parse_tag(cfml_parser_t *parser, cfml_ast_node_t **node)
{
    cfml_token_t *token;
    cfml_ast_node_t *tag_node;
    ngx_str_t tag_name;

    token = cfml_lexer_next_token(parser->lexer);
    if (token->type != CFML_TOKEN_CF_TAG_NAME) {
        cfml_parser_error(parser, "Expected CF tag name");
        return NGX_ERROR;
    }

    tag_name = token->value;

    /* Create appropriate node type based on tag name */
    cfml_ast_type_t ast_type = CFML_AST_TAG_CUSTOM;
    
    if (ngx_strncasecmp(tag_name.data, (u_char *)"set", 3) == 0 && tag_name.len == 3) {
        ast_type = CFML_AST_TAG_SET;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"output", 6) == 0) {
        ast_type = CFML_AST_TAG_OUTPUT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"if", 2) == 0 && tag_name.len == 2) {
        ast_type = CFML_AST_TAG_IF;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"elseif", 6) == 0) {
        ast_type = CFML_AST_TAG_ELSEIF;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"else", 4) == 0 && tag_name.len == 4) {
        ast_type = CFML_AST_TAG_ELSE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"loop", 4) == 0) {
        ast_type = CFML_AST_TAG_LOOP;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"break", 5) == 0) {
        ast_type = CFML_AST_TAG_BREAK;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"continue", 8) == 0) {
        ast_type = CFML_AST_TAG_CONTINUE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"include", 7) == 0) {
        ast_type = CFML_AST_TAG_INCLUDE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"param", 5) == 0) {
        ast_type = CFML_AST_TAG_PARAM;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"function", 8) == 0) {
        ast_type = CFML_AST_TAG_FUNCTION;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"argument", 8) == 0) {
        ast_type = CFML_AST_TAG_ARGUMENT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"return", 6) == 0) {
        ast_type = CFML_AST_TAG_RETURN;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"component", 9) == 0) {
        ast_type = CFML_AST_TAG_COMPONENT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"query", 5) == 0) {
        ast_type = CFML_AST_TAG_QUERY;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"http", 4) == 0 && tag_name.len == 4) {
        ast_type = CFML_AST_TAG_HTTP;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"try", 3) == 0) {
        ast_type = CFML_AST_TAG_TRY;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"catch", 5) == 0) {
        ast_type = CFML_AST_TAG_CATCH;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"finally", 7) == 0) {
        ast_type = CFML_AST_TAG_FINALLY;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"throw", 5) == 0) {
        ast_type = CFML_AST_TAG_THROW;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"switch", 6) == 0) {
        ast_type = CFML_AST_TAG_SWITCH;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"case", 4) == 0) {
        ast_type = CFML_AST_TAG_CASE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"defaultcase", 11) == 0) {
        ast_type = CFML_AST_TAG_DEFAULTCASE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"abort", 5) == 0) {
        ast_type = CFML_AST_TAG_ABORT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"dump", 4) == 0) {
        ast_type = CFML_AST_TAG_DUMP;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"log", 3) == 0) {
        ast_type = CFML_AST_TAG_LOG;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"location", 8) == 0) {
        ast_type = CFML_AST_TAG_LOCATION;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"header", 6) == 0) {
        ast_type = CFML_AST_TAG_HEADER;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"content", 7) == 0) {
        ast_type = CFML_AST_TAG_CONTENT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"cookie", 6) == 0) {
        ast_type = CFML_AST_TAG_COOKIE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"savecontent", 11) == 0) {
        ast_type = CFML_AST_TAG_SAVECONTENT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"script", 6) == 0) {
        ast_type = CFML_AST_SCRIPT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"mail", 4) == 0 && tag_name.len == 4) {
        ast_type = CFML_AST_TAG_MAIL;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"file", 4) == 0) {
        ast_type = CFML_AST_TAG_FILE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"directory", 9) == 0) {
        ast_type = CFML_AST_TAG_DIRECTORY;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"lock", 4) == 0) {
        ast_type = CFML_AST_TAG_LOCK;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"thread", 6) == 0) {
        ast_type = CFML_AST_TAG_THREAD;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"transaction", 11) == 0) {
        ast_type = CFML_AST_TAG_TRANSACTION;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"cache", 5) == 0) {
        ast_type = CFML_AST_TAG_CACHE;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"setting", 7) == 0) {
        ast_type = CFML_AST_TAG_SETTING;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"silent", 6) == 0) {
        ast_type = CFML_AST_TAG_SILENT;
    } else if (ngx_strncasecmp(tag_name.data, (u_char *)"flush", 5) == 0) {
        ast_type = CFML_AST_TAG_FLUSH;
    }

    tag_node = cfml_ast_create_node(parser->pool, ast_type);
    if (tag_node == NULL) {
        return NGX_ERROR;
    }

    tag_node->tag_name = tag_name;
    tag_node->line = token->line;
    tag_node->column = token->column;

    /* Parse attributes */
    while (1) {
        token = cfml_lexer_next_token(parser->lexer);
        
        if (token->type == CFML_TOKEN_TAG_CLOSE) {
            /* Has body - parse content until closing tag */
            if (cfml_parse_tag_content(parser, tag_node, &tag_name) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        }
        
        if (token->type == CFML_TOKEN_TAG_SELF_CLOSE) {
            /* Self-closing tag - no body */
            break;
        }
        
        if (token->type == CFML_TOKEN_IDENTIFIER) {
            /* Attribute */
            ngx_str_t attr_name = token->value;
            cfml_ast_node_t *attr_value = NULL;
            
            token = cfml_lexer_peek_token(parser->lexer);
            if (token->type == CFML_TOKEN_ASSIGN) {
                cfml_lexer_next_token(parser->lexer);
                
                token = cfml_lexer_next_token(parser->lexer);
                if (token->type == CFML_TOKEN_STRING) {
                    /* String value - may contain expressions */
                    attr_value = cfml_ast_create_node(parser->pool, CFML_AST_EXPR_LITERAL);
                    if (attr_value == NULL) {
                        return NGX_ERROR;
                    }
                    attr_value->data.literal = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
                    attr_value->data.literal->type = CFML_TYPE_STRING;
                    attr_value->data.literal->data.string = token->value;
                } else {
                    cfml_parser_error(parser, "Expected attribute value");
                    return NGX_ERROR;
                }
            }
            
            cfml_ast_set_attribute(tag_node, &attr_name, attr_value);
        } else {
            cfml_parser_error(parser, "Expected attribute name or tag end");
            return NGX_ERROR;
        }
    }

    *node = tag_node;
    return NGX_OK;
}

/* Parse tag content until closing tag */
static ngx_int_t
cfml_parse_tag_content(cfml_parser_t *parser, cfml_ast_node_t *parent,
                       ngx_str_t *end_tag)
{
    cfml_token_t *token;

    /* Handle cfoutput context */
    if (parent->type == CFML_AST_TAG_OUTPUT) {
        parser->lexer->output_depth++;
        parser->lexer->state = CFML_LEXER_STATE_OUTPUT;
    }

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type == CFML_TOKEN_EOF) {
            cfml_parser_error(parser, "Unexpected end of file, expected </cf%V>",
                              end_tag);
            return NGX_ERROR;
        }
        
        if (token->type == CFML_TOKEN_TAG_END_OPEN) {
            /* Closing tag */
            cfml_lexer_next_token(parser->lexer);
            token = cfml_lexer_next_token(parser->lexer);
            
            if (token->type == CFML_TOKEN_CF_TAG_NAME) {
                if (token->value.len == end_tag->len &&
                    ngx_strncasecmp(token->value.data, end_tag->data, end_tag->len) == 0) {
                    /* Matching closing tag */
                    cfml_parser_expect(parser, CFML_TOKEN_TAG_CLOSE);
                    
                    if (parent->type == CFML_AST_TAG_OUTPUT) {
                        parser->lexer->output_depth--;
                        if (parser->lexer->output_depth == 0) {
                            parser->lexer->state = CFML_LEXER_STATE_TEXT;
                        }
                    }
                    
                    return NGX_OK;
                }
            }
            
            cfml_parser_error(parser, "Expected </cf%V>, got </cf%V>",
                              end_tag, &token->value);
            return NGX_ERROR;
        }
        
        if (token->type == CFML_TOKEN_TEXT) {
            cfml_lexer_next_token(parser->lexer);
            
            cfml_ast_node_t *text_node = cfml_ast_create_node(parser->pool, CFML_AST_TEXT);
            if (text_node == NULL) {
                return NGX_ERROR;
            }
            text_node->data.text = token->value;
            cfml_ast_add_child(parent, text_node);
        } else if (token->type == CFML_TOKEN_HASH_OPEN) {
            /* Expression in cfoutput */
            cfml_lexer_next_token(parser->lexer);
            
            cfml_ast_node_t *interp_node = cfml_ast_create_node(parser->pool, 
                                                                CFML_AST_EXPR_INTERPOLATION);
            if (interp_node == NULL) {
                return NGX_ERROR;
            }
            
            parser->lexer->state = CFML_LEXER_STATE_EXPRESSION;
            cfml_ast_node_t *expr = cfml_parse_expression(parser);
            if (expr == NULL) {
                return NGX_ERROR;
            }
            
            cfml_ast_add_child(interp_node, expr);
            cfml_ast_add_child(parent, interp_node);
            
            /* Consume closing hash (handled by lexer state change) */
        } else if (token->type == CFML_TOKEN_CF_TAG_NAME || 
                   (token->type == CFML_TOKEN_TAG_OPEN)) {
            /* Nested CF tag */
            cfml_ast_node_t *nested_tag;
            if (cfml_parse_tag(parser, &nested_tag) != NGX_OK) {
                return NGX_ERROR;
            }
            cfml_ast_add_child(parent, nested_tag);
        } else if (token->type == CFML_TOKEN_COMMENT) {
            /* Skip comments */
            cfml_lexer_next_token(parser->lexer);
        } else {
            cfml_lexer_next_token(parser->lexer);
        }
    }
}

/* Parse template content */
static ngx_int_t
cfml_parse_template_content(cfml_parser_t *parser, cfml_ast_node_t *parent)
{
    cfml_token_t *token;

    while (1) {
        token = cfml_lexer_peek_token(parser->lexer);
        
        if (token->type == CFML_TOKEN_EOF) {
            break;
        }
        
        if (token->type == CFML_TOKEN_TEXT) {
            cfml_lexer_next_token(parser->lexer);
            
            cfml_ast_node_t *text_node = cfml_ast_create_node(parser->pool, CFML_AST_TEXT);
            if (text_node == NULL) {
                return NGX_ERROR;
            }
            text_node->data.text = token->value;
            cfml_ast_add_child(parent, text_node);
        } else if (token->type == CFML_TOKEN_CF_TAG_NAME) {
            cfml_ast_node_t *tag_node;
            if (cfml_parse_tag(parser, &tag_node) != NGX_OK) {
                return NGX_ERROR;
            }
            cfml_ast_add_child(parent, tag_node);
        } else if (token->type == CFML_TOKEN_COMMENT) {
            /* Skip comments */
            cfml_lexer_next_token(parser->lexer);
        } else {
            /* Skip other tokens (HTML, etc.) */
            cfml_lexer_next_token(parser->lexer);
        }
    }

    return NGX_OK;
}

/* Parse template file */
cfml_template_t *
cfml_parse_template(ngx_pool_t *pool, ngx_str_t *path, ngx_flag_t use_cache)
{
    cfml_template_t *tmpl;
    cfml_parser_t *parser;
    ngx_file_t file;
    ngx_file_info_t fi;
    u_char *content;
    ssize_t n;

    /* Check cache */
    if (use_cache) {
        tmpl = cfml_cache_get(path);
        if (tmpl != NULL && !cfml_cache_is_stale(path, tmpl)) {
            return tmpl;
        }
    }

    /* Open file */
    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *path;
    file.log = pool->log;

    file.fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", path);
        return NULL;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", path);
        ngx_close_file(file.fd);
        return NULL;
    }

    content = ngx_pnalloc(pool, ngx_file_size(&fi) + 1);
    if (content == NULL) {
        ngx_close_file(file.fd);
        return NULL;
    }

    n = ngx_read_file(&file, content, ngx_file_size(&fi), 0);
    ngx_close_file(file.fd);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno,
                      ngx_read_file_n " \"%V\" failed", path);
        return NULL;
    }

    content[n] = '\0';

    /* Create parser */
    parser = cfml_parser_create(pool, content, n);
    if (parser == NULL) {
        return NULL;
    }

    /* Create root node */
    parser->template->root = cfml_ast_create_node(pool, CFML_AST_ROOT);
    if (parser->template->root == NULL) {
        cfml_parser_destroy(parser);
        return NULL;
    }

    parser->template->path = *path;
    parser->template->mtime = ngx_file_mtime(&fi);

    /* Parse content */
    if (cfml_parse_template_content(parser, parser->template->root) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "CFML parse error at line %ui: %V",
                      parser->error_line, &parser->error_message);
        cfml_parser_destroy(parser);
        return NULL;
    }

    tmpl = parser->template;

    /* Cache the template */
    if (use_cache) {
        cfml_cache_put(path, tmpl);
    }

    cfml_parser_destroy(parser);

    return tmpl;
}

/* Parse string */
cfml_template_t *
cfml_parse_string(ngx_pool_t *pool, ngx_str_t *content)
{
    cfml_parser_t *parser;
    cfml_template_t *tmpl;

    parser = cfml_parser_create(pool, content->data, content->len);
    if (parser == NULL) {
        return NULL;
    }

    parser->template->root = cfml_ast_create_node(pool, CFML_AST_ROOT);
    if (parser->template->root == NULL) {
        cfml_parser_destroy(parser);
        return NULL;
    }

    if (cfml_parse_template_content(parser, parser->template->root) != NGX_OK) {
        cfml_parser_destroy(parser);
        return NULL;
    }

    tmpl = parser->template;
    cfml_parser_destroy(parser);

    return tmpl;
}

/* Get AST type name for debugging */
const char *
cfml_ast_type_name(cfml_ast_type_t type)
{
    static const char *names[] = {
        "ROOT", "TEMPLATE",
        "TEXT", "COMMENT",
        "TAG_SET", "TAG_OUTPUT", "TAG_IF", "TAG_ELSEIF", "TAG_ELSE",
        "TAG_LOOP", "TAG_BREAK", "TAG_CONTINUE",
        /* ... more would be added */
    };

    if ((size_t)type < sizeof(names) / sizeof(names[0])) {
        return names[type];
    }

    return "UNKNOWN";
}
