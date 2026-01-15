/*
 * CFML CFScript - Full CFScript language support
 */

#ifndef _CFML_CFSCRIPT_H_
#define _CFML_CFSCRIPT_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* CFScript-specific token types */
typedef enum {
    /* Keywords */
    CFSCRIPT_KW_COMPONENT = 500,
    CFSCRIPT_KW_INTERFACE,
    CFSCRIPT_KW_FUNCTION,
    CFSCRIPT_KW_PUBLIC,
    CFSCRIPT_KW_PRIVATE,
    CFSCRIPT_KW_REMOTE,
    CFSCRIPT_KW_PACKAGE,
    CFSCRIPT_KW_STATIC,
    CFSCRIPT_KW_FINAL,
    CFSCRIPT_KW_ABSTRACT,
    CFSCRIPT_KW_VAR,
    CFSCRIPT_KW_LOCAL,
    CFSCRIPT_KW_IF,
    CFSCRIPT_KW_ELSE,
    CFSCRIPT_KW_SWITCH,
    CFSCRIPT_KW_CASE,
    CFSCRIPT_KW_DEFAULT,
    CFSCRIPT_KW_FOR,
    CFSCRIPT_KW_WHILE,
    CFSCRIPT_KW_DO,
    CFSCRIPT_KW_IN,
    CFSCRIPT_KW_BREAK,
    CFSCRIPT_KW_CONTINUE,
    CFSCRIPT_KW_RETURN,
    CFSCRIPT_KW_TRY,
    CFSCRIPT_KW_CATCH,
    CFSCRIPT_KW_FINALLY,
    CFSCRIPT_KW_THROW,
    CFSCRIPT_KW_RETHROW,
    CFSCRIPT_KW_NEW,
    CFSCRIPT_KW_IMPORT,
    CFSCRIPT_KW_REQUIRED,
    CFSCRIPT_KW_PARAM,
    CFSCRIPT_KW_PROPERTY,
    CFSCRIPT_KW_INCLUDE,
    CFSCRIPT_KW_ABORT,
    CFSCRIPT_KW_EXIT,
    CFSCRIPT_KW_LOCK,
    CFSCRIPT_KW_THREAD,
    CFSCRIPT_KW_TRANSACTION,
    CFSCRIPT_KW_SAVECONTENT,
    CFSCRIPT_KW_TRUE,
    CFSCRIPT_KW_FALSE,
    CFSCRIPT_KW_NULL,
    
    /* Type keywords */
    CFSCRIPT_TYPE_ANY,
    CFSCRIPT_TYPE_ARRAY,
    CFSCRIPT_TYPE_BINARY,
    CFSCRIPT_TYPE_BOOLEAN,
    CFSCRIPT_TYPE_DATE,
    CFSCRIPT_TYPE_GUID,
    CFSCRIPT_TYPE_NUMERIC,
    CFSCRIPT_TYPE_QUERY,
    CFSCRIPT_TYPE_STRING,
    CFSCRIPT_TYPE_STRUCT,
    CFSCRIPT_TYPE_UUID,
    CFSCRIPT_TYPE_VOID,
    CFSCRIPT_TYPE_XML,
    
    /* Operators */
    CFSCRIPT_OP_ASSIGN,         /* = */
    CFSCRIPT_OP_ASSIGN_ADD,     /* += */
    CFSCRIPT_OP_ASSIGN_SUB,     /* -= */
    CFSCRIPT_OP_ASSIGN_MUL,     /* *= */
    CFSCRIPT_OP_ASSIGN_DIV,     /* /= */
    CFSCRIPT_OP_ASSIGN_MOD,     /* %= */
    CFSCRIPT_OP_ASSIGN_CONCAT,  /* &= */
    CFSCRIPT_OP_INCREMENT,      /* ++ */
    CFSCRIPT_OP_DECREMENT,      /* -- */
    CFSCRIPT_OP_TERNARY,        /* ? */
    CFSCRIPT_OP_COLON,          /* : */
    CFSCRIPT_OP_ELVIS,          /* ?: */
    CFSCRIPT_OP_NULL_COALESCE,  /* ?? */
    CFSCRIPT_OP_SAFE_NAV,       /* ?. */
    CFSCRIPT_OP_SPREAD,         /* ... */
    CFSCRIPT_OP_ARROW,          /* => */
    CFSCRIPT_OP_ARROW2,         /* -> */
    
    /* Comparison */
    CFSCRIPT_OP_EQ,             /* == */
    CFSCRIPT_OP_NEQ,            /* != */
    CFSCRIPT_OP_STRICT_EQ,      /* === */
    CFSCRIPT_OP_STRICT_NEQ,     /* !== */
    CFSCRIPT_OP_LT,             /* < */
    CFSCRIPT_OP_GT,             /* > */
    CFSCRIPT_OP_LTE,            /* <= */
    CFSCRIPT_OP_GTE,            /* >= */
    
    /* Logical */
    CFSCRIPT_OP_AND,            /* && */
    CFSCRIPT_OP_OR,             /* || */
    CFSCRIPT_OP_NOT,            /* ! */
    
    /* Arithmetic */
    CFSCRIPT_OP_ADD,            /* + */
    CFSCRIPT_OP_SUB,            /* - */
    CFSCRIPT_OP_MUL,            /* * */
    CFSCRIPT_OP_DIV,            /* / */
    CFSCRIPT_OP_MOD,            /* % */
    CFSCRIPT_OP_POWER,          /* ^ */
    CFSCRIPT_OP_INTDIV,         /* \ */
    
    /* String */
    CFSCRIPT_OP_CONCAT,         /* & */
    
    /* Punctuation */
    CFSCRIPT_LPAREN,
    CFSCRIPT_RPAREN,
    CFSCRIPT_LBRACE,
    CFSCRIPT_RBRACE,
    CFSCRIPT_LBRACKET,
    CFSCRIPT_RBRACKET,
    CFSCRIPT_SEMICOLON,
    CFSCRIPT_COMMA,
    CFSCRIPT_DOT,
    
    /* Literals */
    CFSCRIPT_NUMBER,
    CFSCRIPT_STRING,
    CFSCRIPT_IDENTIFIER,
    CFSCRIPT_COMMENT,
    
    /* Special */
    CFSCRIPT_EOF,
    CFSCRIPT_NEWLINE,
    CFSCRIPT_ERROR
} cfscript_token_type_t;

/* CFScript token */
typedef struct {
    cfscript_token_type_t   type;
    ngx_str_t               value;
    ngx_uint_t              line;
    ngx_uint_t              column;
} cfscript_token_t;

/* CFScript lexer state */
typedef struct {
    u_char                  *start;
    u_char                  *end;
    u_char                  *pos;
    ngx_uint_t              line;
    ngx_uint_t              column;
    ngx_pool_t              *pool;
    cfscript_token_t        *current;
    cfscript_token_t        *peek;
} cfscript_lexer_t;

/* CFScript AST node types */
typedef enum {
    CFSCRIPT_AST_PROGRAM = 0,
    CFSCRIPT_AST_COMPONENT,
    CFSCRIPT_AST_INTERFACE,
    CFSCRIPT_AST_PROPERTY,
    CFSCRIPT_AST_FUNCTION,
    CFSCRIPT_AST_PARAM,
    CFSCRIPT_AST_BLOCK,
    CFSCRIPT_AST_VAR_DECL,
    CFSCRIPT_AST_IF,
    CFSCRIPT_AST_SWITCH,
    CFSCRIPT_AST_CASE,
    CFSCRIPT_AST_FOR,
    CFSCRIPT_AST_FOR_IN,
    CFSCRIPT_AST_WHILE,
    CFSCRIPT_AST_DO_WHILE,
    CFSCRIPT_AST_BREAK,
    CFSCRIPT_AST_CONTINUE,
    CFSCRIPT_AST_RETURN,
    CFSCRIPT_AST_TRY,
    CFSCRIPT_AST_CATCH,
    CFSCRIPT_AST_FINALLY,
    CFSCRIPT_AST_THROW,
    CFSCRIPT_AST_IMPORT,
    CFSCRIPT_AST_LOCK,
    CFSCRIPT_AST_THREAD,
    CFSCRIPT_AST_TRANSACTION,
    CFSCRIPT_AST_SAVECONTENT,
    CFSCRIPT_AST_INCLUDE,
    CFSCRIPT_AST_ABORT,
    CFSCRIPT_AST_EXIT,
    CFSCRIPT_AST_PARAM_TAG,
    CFSCRIPT_AST_EXPRESSION_STMT,
    CFSCRIPT_AST_ASSIGNMENT,
    CFSCRIPT_AST_COMPOUND_ASSIGN,
    CFSCRIPT_AST_TERNARY,
    CFSCRIPT_AST_BINARY,
    CFSCRIPT_AST_UNARY,
    CFSCRIPT_AST_PREFIX,
    CFSCRIPT_AST_POSTFIX,
    CFSCRIPT_AST_CALL,
    CFSCRIPT_AST_METHOD_CALL,
    CFSCRIPT_AST_NEW,
    CFSCRIPT_AST_MEMBER,
    CFSCRIPT_AST_INDEX,
    CFSCRIPT_AST_ARRAY_LITERAL,
    CFSCRIPT_AST_STRUCT_LITERAL,
    CFSCRIPT_AST_CLOSURE,
    CFSCRIPT_AST_IDENTIFIER,
    CFSCRIPT_AST_LITERAL_NUMBER,
    CFSCRIPT_AST_LITERAL_STRING,
    CFSCRIPT_AST_LITERAL_BOOLEAN,
    CFSCRIPT_AST_LITERAL_NULL,
    CFSCRIPT_AST_INTERPOLATED_STRING
} cfscript_ast_type_t;

/* CFScript AST node */
typedef struct cfscript_ast_node_s cfscript_ast_node_t;

struct cfscript_ast_node_s {
    cfscript_ast_type_t     type;
    ngx_uint_t              line;
    ngx_uint_t              column;
    ngx_pool_t              *pool;
    
    union {
        /* Component/Interface */
        struct {
            ngx_str_t       name;
            ngx_str_t       extends;
            ngx_str_t       implements;
            ngx_array_t     *properties;    /* cfscript_ast_node_t* */
            ngx_array_t     *functions;     /* cfscript_ast_node_t* */
            ngx_array_t     *metadata;      /* key-value pairs */
        } component;
        
        /* Function */
        struct {
            ngx_str_t       name;
            ngx_str_t       return_type;
            ngx_str_t       access;
            ngx_array_t     *params;        /* cfscript_ast_node_t* */
            cfscript_ast_node_t *body;
            unsigned        is_static:1;
            unsigned        is_final:1;
            unsigned        is_abstract:1;
        } function;
        
        /* Parameter */
        struct {
            ngx_str_t       name;
            ngx_str_t       type;
            cfscript_ast_node_t *default_value;
            unsigned        required:1;
        } param;
        
        /* Property */
        struct {
            ngx_str_t       name;
            ngx_str_t       type;
            cfscript_ast_node_t *default_value;
            ngx_str_t       getter;
            ngx_str_t       setter;
        } property;
        
        /* Variable declaration */
        struct {
            ngx_str_t       name;
            ngx_str_t       type;
            cfscript_ast_node_t *init;
            unsigned        is_local:1;
        } var_decl;
        
        /* If statement */
        struct {
            cfscript_ast_node_t *condition;
            cfscript_ast_node_t *then_branch;
            cfscript_ast_node_t *else_branch;
        } if_stmt;
        
        /* Switch statement */
        struct {
            cfscript_ast_node_t *expression;
            ngx_array_t     *cases;         /* cfscript_ast_node_t* */
            cfscript_ast_node_t *default_case;
        } switch_stmt;
        
        /* Case */
        struct {
            ngx_array_t     *values;        /* cfscript_ast_node_t* */
            ngx_array_t     *statements;    /* cfscript_ast_node_t* */
        } case_stmt;
        
        /* For loop */
        struct {
            cfscript_ast_node_t *init;
            cfscript_ast_node_t *condition;
            cfscript_ast_node_t *update;
            cfscript_ast_node_t *body;
        } for_loop;
        
        /* For-in loop */
        struct {
            ngx_str_t       variable;
            ngx_str_t       index;
            cfscript_ast_node_t *collection;
            cfscript_ast_node_t *body;
        } for_in;
        
        /* While loop */
        struct {
            cfscript_ast_node_t *condition;
            cfscript_ast_node_t *body;
        } while_loop;
        
        /* Try-catch */
        struct {
            cfscript_ast_node_t *try_block;
            ngx_array_t     *catch_blocks;  /* cfscript_ast_node_t* */
            cfscript_ast_node_t *finally_block;
        } try_stmt;
        
        /* Catch */
        struct {
            ngx_str_t       type;
            ngx_str_t       variable;
            cfscript_ast_node_t *body;
        } catch_stmt;
        
        /* Binary expression */
        struct {
            cfscript_token_type_t op;
            cfscript_ast_node_t *left;
            cfscript_ast_node_t *right;
        } binary;
        
        /* Unary expression */
        struct {
            cfscript_token_type_t op;
            cfscript_ast_node_t *operand;
            unsigned        is_prefix:1;
        } unary;
        
        /* Ternary expression */
        struct {
            cfscript_ast_node_t *condition;
            cfscript_ast_node_t *then_expr;
            cfscript_ast_node_t *else_expr;
        } ternary;
        
        /* Function call */
        struct {
            cfscript_ast_node_t *callee;
            ngx_array_t     *arguments;     /* cfscript_ast_node_t* */
        } call;
        
        /* Member access */
        struct {
            cfscript_ast_node_t *object;
            ngx_str_t       property;
            unsigned        safe_navigation:1;
        } member;
        
        /* Index access */
        struct {
            cfscript_ast_node_t *object;
            cfscript_ast_node_t *index;
        } index;
        
        /* New expression */
        struct {
            ngx_str_t       component;
            ngx_array_t     *arguments;
        } new_expr;
        
        /* Closure */
        struct {
            ngx_array_t     *params;
            cfscript_ast_node_t *body;
            unsigned        is_arrow:1;
        } closure;
        
        /* Literals */
        ngx_str_t           string;
        double              number;
        ngx_flag_t          boolean;
        ngx_str_t           identifier;
        
        /* Block */
        ngx_array_t         *statements;
        
        /* Lock */
        struct {
            ngx_str_t       name;
            ngx_str_t       scope;
            ngx_str_t       type;
            ngx_msec_t      timeout;
            cfscript_ast_node_t *body;
        } lock_stmt;
        
        /* Thread */
        struct {
            ngx_str_t       name;
            ngx_str_t       action;
            ngx_msec_t      timeout;
            cfscript_ast_node_t *body;
        } thread_stmt;
        
        /* Transaction */
        struct {
            ngx_str_t       action;
            cfscript_ast_node_t *body;
        } transaction;
        
        /* SaveContent */
        struct {
            ngx_str_t       variable;
            cfscript_ast_node_t *body;
        } savecontent;
        
        /* Include */
        struct {
            ngx_str_t       template;
        } include;
        
        /* Throw */
        struct {
            cfscript_ast_node_t *expression;
            ngx_str_t       type;
            ngx_str_t       message;
        } throw_stmt;
        
        /* Import */
        struct {
            ngx_str_t       path;
        } import_stmt;
        
        /* Return */
        cfscript_ast_node_t *return_value;
        
    } data;
};

/* CFScript parser */
typedef struct {
    cfscript_lexer_t        *lexer;
    ngx_pool_t              *pool;
    ngx_str_t               error;
    ngx_uint_t              error_line;
    ngx_uint_t              error_column;
} cfscript_parser_t;

/* Lexer functions */
cfscript_lexer_t *cfscript_lexer_create(ngx_pool_t *pool, u_char *input, size_t len);
cfscript_token_t *cfscript_lexer_next(cfscript_lexer_t *lexer);
cfscript_token_t *cfscript_lexer_peek(cfscript_lexer_t *lexer);
void cfscript_lexer_destroy(cfscript_lexer_t *lexer);

/* Parser functions */
cfscript_parser_t *cfscript_parser_create(ngx_pool_t *pool, u_char *input, size_t len);
cfscript_ast_node_t *cfscript_parse(cfscript_parser_t *parser);
cfscript_ast_node_t *cfscript_parse_component(cfscript_parser_t *parser);
cfscript_ast_node_t *cfscript_parse_function(cfscript_parser_t *parser);
cfscript_ast_node_t *cfscript_parse_statement(cfscript_parser_t *parser);
cfscript_ast_node_t *cfscript_parse_expression(cfscript_parser_t *parser);
void cfscript_parser_destroy(cfscript_parser_t *parser);

/* Execution */
ngx_int_t cfscript_execute(cfml_context_t *ctx, cfscript_ast_node_t *node);
cfml_value_t *cfscript_eval(cfml_context_t *ctx, cfscript_ast_node_t *node);

/* AST conversion (to standard CFML AST for unified execution) */
cfml_ast_node_t *cfscript_to_cfml_ast(ngx_pool_t *pool, cfscript_ast_node_t *node);

#endif /* _CFML_CFSCRIPT_H_ */
