/*
 * CFML Parser - Parse CFML source into AST
 */

#ifndef _CFML_PARSER_H_
#define _CFML_PARSER_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"
#include "cfml_lexer.h"

/* Parser context */
typedef struct {
    cfml_lexer_t        *lexer;
    ngx_pool_t          *pool;
    cfml_template_t     *template;
    
    /* Current state */
    cfml_token_t        *current_token;
    ngx_uint_t          in_output;
    ngx_uint_t          in_script;
    
    /* Error handling */
    ngx_str_t           error_message;
    ngx_uint_t          error_line;
    ngx_uint_t          error_column;
    
    /* Options */
    unsigned            strict_mode:1;
} cfml_parser_t;

/* Function prototypes */

/* Main parsing functions */
cfml_template_t *cfml_parse_template(ngx_pool_t *pool, ngx_str_t *path, 
                                     ngx_flag_t use_cache);
cfml_template_t *cfml_parse_string(ngx_pool_t *pool, ngx_str_t *content);
cfml_ast_node_t *cfml_parse_expression(cfml_parser_t *parser);

/* Parser creation/destruction */
cfml_parser_t *cfml_parser_create(ngx_pool_t *pool, u_char *input, size_t len);
void cfml_parser_destroy(cfml_parser_t *parser);

/* AST node creation */
cfml_ast_node_t *cfml_ast_create_node(ngx_pool_t *pool, cfml_ast_type_t type);
void cfml_ast_add_child(cfml_ast_node_t *parent, cfml_ast_node_t *child);
void cfml_ast_set_attribute(cfml_ast_node_t *node, ngx_str_t *name, 
                            cfml_ast_node_t *value);
cfml_ast_node_t *cfml_ast_get_attribute(cfml_ast_node_t *node, ngx_str_t *name);

/* Parsing helpers */
ngx_int_t cfml_parse_tag(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_cfscript(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_statement(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_block(cfml_parser_t *parser, cfml_ast_node_t **node);

/* Expression parsing */
ngx_int_t cfml_parse_assignment_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_ternary_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_or_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_and_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_equality_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_relational_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_additive_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_multiplicative_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_unary_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_postfix_expr(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_primary_expr(cfml_parser_t *parser, cfml_ast_node_t **node);

/* Literal parsing */
ngx_int_t cfml_parse_array_literal(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_struct_literal(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_function_literal(cfml_parser_t *parser, cfml_ast_node_t **node);

/* Component parsing */
ngx_int_t cfml_parse_component(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_function_def(cfml_parser_t *parser, cfml_ast_node_t **node);
ngx_int_t cfml_parse_property(cfml_parser_t *parser, cfml_ast_node_t **node);

/* Connection string parsing */
ngx_int_t cfml_parse_connection_string(ngx_pool_t *pool, ngx_str_t *conn_str,
                                       cfml_datasource_t *ds);

/* Error handling */
void cfml_parser_error(cfml_parser_t *parser, const char *fmt, ...);

/* Debug/utility */
void cfml_ast_dump(cfml_ast_node_t *node, ngx_uint_t depth);
const char *cfml_ast_type_name(cfml_ast_type_t type);

#endif /* _CFML_PARSER_H_ */
