/*
 * ngx_http_cfml_module - CFML type definitions
 * Copyright (c) 2026
 */

#ifndef _CFML_TYPES_H_
#define _CFML_TYPES_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Forward declarations */
typedef struct cfml_value_s cfml_value_t;
typedef struct cfml_array_s cfml_array_t;
typedef struct cfml_struct_s cfml_struct_t;
typedef struct cfml_query_s cfml_query_t;
typedef struct cfml_function_s cfml_function_t;
typedef struct cfml_component_s cfml_component_t;
typedef struct cfml_scope_s cfml_scope_t;
typedef struct cfml_context_s cfml_context_t;
typedef struct cfml_ast_node_s cfml_ast_node_t;
typedef struct cfml_template_s cfml_template_t;

/* Value types */
typedef enum {
    CFML_TYPE_NULL = 0,
    CFML_TYPE_BOOLEAN,
    CFML_TYPE_INTEGER,
    CFML_TYPE_FLOAT,
    CFML_TYPE_STRING,
    CFML_TYPE_DATE,
    CFML_TYPE_ARRAY,
    CFML_TYPE_STRUCT,
    CFML_TYPE_QUERY,
    CFML_TYPE_FUNCTION,
    CFML_TYPE_COMPONENT,
    CFML_TYPE_BINARY,
    CFML_TYPE_XML,
    CFML_TYPE_JAVA_OBJECT
} cfml_type_t;

/* AST node types */
typedef enum {
    /* Root */
    CFML_AST_ROOT = 0,
    CFML_AST_TEMPLATE,
    
    /* Literal content */
    CFML_AST_TEXT,
    CFML_AST_COMMENT,
    
    /* Tags */
    CFML_AST_TAG_SET,
    CFML_AST_TAG_OUTPUT,
    CFML_AST_TAG_IF,
    CFML_AST_TAG_ELSEIF,
    CFML_AST_TAG_ELSE,
    CFML_AST_TAG_LOOP,
    CFML_AST_TAG_BREAK,
    CFML_AST_TAG_CONTINUE,
    CFML_AST_TAG_INCLUDE,
    CFML_AST_TAG_PARAM,
    CFML_AST_TAG_FUNCTION,
    CFML_AST_TAG_ARGUMENT,
    CFML_AST_TAG_RETURN,
    CFML_AST_TAG_COMPONENT,
    CFML_AST_TAG_PROPERTY,
    CFML_AST_TAG_INVOKE,
    CFML_AST_TAG_QUERY,
    CFML_AST_TAG_HTTP,
    CFML_AST_TAG_HTTPPARAM,
    CFML_AST_TAG_TRY,
    CFML_AST_TAG_CATCH,
    CFML_AST_TAG_FINALLY,
    CFML_AST_TAG_THROW,
    CFML_AST_TAG_RETHROW,
    CFML_AST_TAG_SWITCH,
    CFML_AST_TAG_CASE,
    CFML_AST_TAG_DEFAULTCASE,
    CFML_AST_TAG_ABORT,
    CFML_AST_TAG_EXIT,
    CFML_AST_TAG_DUMP,
    CFML_AST_TAG_LOG,
    CFML_AST_TAG_LOCATION,
    CFML_AST_TAG_HEADER,
    CFML_AST_TAG_CONTENT,
    CFML_AST_TAG_COOKIE,
    CFML_AST_TAG_SAVECONTENT,
    CFML_AST_TAG_SETTING,
    CFML_AST_TAG_LOCK,
    CFML_AST_TAG_THREAD,
    CFML_AST_TAG_TRANSACTION,
    CFML_AST_TAG_STOREDPROC,
    CFML_AST_TAG_PROCPARAM,
    CFML_AST_TAG_PROCRESULT,
    CFML_AST_TAG_FILE,
    CFML_AST_TAG_DIRECTORY,
    CFML_AST_TAG_MAIL,
    CFML_AST_TAG_MAILPARAM,
    CFML_AST_TAG_MAILPART,
    CFML_AST_TAG_SCHEDULE,
    CFML_AST_TAG_CACHE,
    CFML_AST_TAG_FLUSH,
    CFML_AST_TAG_SILENT,
    CFML_AST_TAG_CUSTOM,
    
    /* CFScript */
    CFML_AST_SCRIPT,
    CFML_AST_SCRIPT_BLOCK,
    CFML_AST_SCRIPT_VAR,
    CFML_AST_SCRIPT_IF,
    CFML_AST_SCRIPT_ELSE,
    CFML_AST_SCRIPT_SWITCH,
    CFML_AST_SCRIPT_CASE,
    CFML_AST_SCRIPT_DEFAULT,
    CFML_AST_SCRIPT_FOR,
    CFML_AST_SCRIPT_FORIN,
    CFML_AST_SCRIPT_WHILE,
    CFML_AST_SCRIPT_DO,
    CFML_AST_SCRIPT_TRY,
    CFML_AST_SCRIPT_CATCH,
    CFML_AST_SCRIPT_FINALLY,
    CFML_AST_SCRIPT_THROW,
    CFML_AST_SCRIPT_RETHROW,
    CFML_AST_SCRIPT_RETURN,
    CFML_AST_SCRIPT_BREAK,
    CFML_AST_SCRIPT_CONTINUE,
    CFML_AST_SCRIPT_FUNCTION,
    CFML_AST_SCRIPT_COMPONENT,
    CFML_AST_SCRIPT_IMPORT,
    CFML_AST_SCRIPT_NEW,
    
    /* Expressions */
    CFML_AST_EXPR_LITERAL,
    CFML_AST_EXPR_VARIABLE,
    CFML_AST_EXPR_ARRAY_ACCESS,
    CFML_AST_EXPR_STRUCT_ACCESS,
    CFML_AST_EXPR_FUNCTION_CALL,
    CFML_AST_EXPR_METHOD_CALL,
    CFML_AST_EXPR_UNARY,
    CFML_AST_EXPR_BINARY,
    CFML_AST_EXPR_TERNARY,
    CFML_AST_EXPR_ARRAY_LITERAL,
    CFML_AST_EXPR_STRUCT_LITERAL,
    CFML_AST_EXPR_ASSIGNMENT,
    CFML_AST_EXPR_COMPOUND_ASSIGNMENT,
    CFML_AST_EXPR_INCREMENT,
    CFML_AST_EXPR_INTERPOLATION
} cfml_ast_type_t;

/* Binary operators */
typedef enum {
    CFML_OP_ADD = 0,
    CFML_OP_SUB,
    CFML_OP_MUL,
    CFML_OP_DIV,
    CFML_OP_MOD,
    CFML_OP_POW,
    CFML_OP_INTDIV,
    CFML_OP_CONCAT,
    CFML_OP_EQ,
    CFML_OP_NEQ,
    CFML_OP_LT,
    CFML_OP_LTE,
    CFML_OP_GT,
    CFML_OP_GTE,
    CFML_OP_AND,
    CFML_OP_OR,
    CFML_OP_XOR,
    CFML_OP_EQV,
    CFML_OP_IMP,
    CFML_OP_CONTAINS,
    CFML_OP_NOT_CONTAINS,
    CFML_OP_BITAND,
    CFML_OP_BITOR,
    CFML_OP_BITXOR
} cfml_binary_op_t;

/* Unary operators */
typedef enum {
    CFML_OP_NOT = 0,
    CFML_OP_NEG,
    CFML_OP_POS,
    CFML_OP_BITNOT,
    CFML_OP_PRE_INC,
    CFML_OP_PRE_DEC,
    CFML_OP_POST_INC,
    CFML_OP_POST_DEC
} cfml_unary_op_t;

/* Scope types */
typedef enum {
    CFML_SCOPE_VARIABLES = 0,
    CFML_SCOPE_LOCAL,
    CFML_SCOPE_ARGUMENTS,
    CFML_SCOPE_URL,
    CFML_SCOPE_FORM,
    CFML_SCOPE_CGI,
    CFML_SCOPE_COOKIE,
    CFML_SCOPE_REQUEST,
    CFML_SCOPE_SESSION,
    CFML_SCOPE_APPLICATION,
    CFML_SCOPE_SERVER,
    CFML_SCOPE_CLIENT,
    CFML_SCOPE_THIS,
    CFML_SCOPE_SUPER,
    CFML_SCOPE_CALLER,
    CFML_SCOPE_ATTRIBUTES,
    CFML_SCOPE_THREAD,
    CFML_SCOPE_CFTHREAD
} cfml_scope_type_t;

/* Loop types */
typedef enum {
    CFML_LOOP_INDEX = 0,
    CFML_LOOP_CONDITION,
    CFML_LOOP_LIST,
    CFML_LOOP_ARRAY,
    CFML_LOOP_STRUCT,
    CFML_LOOP_QUERY,
    CFML_LOOP_FILE
} cfml_loop_type_t;

/* CFML value structure */
struct cfml_value_s {
    cfml_type_t         type;
    union {
        ngx_int_t       boolean;
        int64_t         integer;
        double          floating;
        ngx_str_t       string;
        struct {
            time_t      time;
            int         tz_offset;
        } date;
        cfml_array_t    *array;
        cfml_struct_t   *structure;
        cfml_query_t    *query;
        cfml_function_t *function;
        cfml_component_t *component;
        struct {
            u_char      *data;
            size_t      len;
        } binary;
    } data;
    ngx_pool_t          *pool;
    unsigned            constant:1;
    unsigned            is_null:1;
};

/* Array structure */
struct cfml_array_s {
    ngx_array_t         *items;     /* Array of cfml_value_t* */
    ngx_pool_t          *pool;
    size_t              capacity;
};

/* Struct key-value entry */
typedef struct {
    ngx_str_t           key;
    ngx_uint_t          key_hash;
    cfml_value_t        *value;
} cfml_struct_entry_t;

/* Struct structure */
struct cfml_struct_s {
    ngx_hash_t          hash;
    ngx_array_t         *keys;      /* Ordered key list for iteration */
    ngx_array_t         *entries;   /* Array of cfml_struct_entry_t */
    ngx_pool_t          *pool;
    unsigned            case_sensitive:1;
    unsigned            ordered:1;
};

/* Query column */
typedef struct {
    ngx_str_t           name;
    cfml_type_t         type;
    ngx_array_t         *data;      /* Array of cfml_value_t* */
} cfml_query_column_t;

/* Query structure */
struct cfml_query_s {
    ngx_str_t           name;
    ngx_array_t         *columns;   /* Array of cfml_query_column_t */
    ngx_hash_t          column_hash;
    size_t              row_count;
    size_t              current_row;
    ngx_pool_t          *pool;
    ngx_str_t           sql;
    ngx_msec_t          execution_time;
    unsigned            cached:1;
};

/* Function argument definition */
typedef struct {
    ngx_str_t           name;
    cfml_type_t         type;
    cfml_value_t        *default_value;
    unsigned            required:1;
} cfml_argument_def_t;

/* Function structure */
struct cfml_function_s {
    ngx_str_t           name;
    ngx_str_t           return_type;
    ngx_array_t         *arguments;     /* Array of cfml_argument_def_t */
    cfml_ast_node_t     *body;
    cfml_component_t    *owner;
    ngx_str_t           access;         /* public, private, package, remote */
    ngx_str_t           output;
    ngx_str_t           description;
    ngx_pool_t          *pool;
    unsigned            is_builtin:1;
    void                *builtin_handler;
};

/* Component property */
typedef struct {
    ngx_str_t           name;
    cfml_type_t         type;
    cfml_value_t        *default_value;
    ngx_str_t           getter;
    ngx_str_t           setter;
    unsigned            serializable:1;
} cfml_property_t;

/* Component structure */
struct cfml_component_s {
    ngx_str_t           name;
    ngx_str_t           full_path;
    ngx_str_t           extends;
    ngx_str_t           implements;
    ngx_array_t         *properties;    /* Array of cfml_property_t */
    ngx_hash_t          functions;      /* Hash of cfml_function_t */
    cfml_struct_t       *this_scope;
    cfml_component_t    *parent;
    ngx_pool_t          *pool;
    ngx_str_t           output;
    ngx_str_t           persistent;
    unsigned            is_interface:1;
    unsigned            accessors:1;
};

/* Variable scope structure */
struct cfml_scope_s {
    cfml_scope_type_t   type;
    cfml_struct_t       *variables;
    struct cfml_scope_s *parent;
    ngx_pool_t          *pool;
};

/* AST node attribute */
typedef struct {
    ngx_str_t           name;
    cfml_ast_node_t     *value;
} cfml_ast_attr_t;

/* AST node structure */
struct cfml_ast_node_s {
    cfml_ast_type_t     type;
    ngx_str_t           tag_name;
    
    /* Position info for error reporting */
    ngx_uint_t          line;
    ngx_uint_t          column;
    
    /* Attributes (for tags) */
    ngx_array_t         *attributes;    /* Array of cfml_ast_attr_t */
    
    /* Children nodes */
    ngx_array_t         *children;      /* Array of cfml_ast_node_t* */
    
    /* Expression-specific data */
    union {
        /* Literal value */
        cfml_value_t    *literal;
        
        /* Variable reference */
        struct {
            ngx_str_t   name;
            cfml_scope_type_t scope;
        } variable;
        
        /* Binary expression */
        struct {
            cfml_binary_op_t op;
            cfml_ast_node_t *left;
            cfml_ast_node_t *right;
        } binary;
        
        /* Unary expression */
        struct {
            cfml_unary_op_t op;
            cfml_ast_node_t *operand;
        } unary;
        
        /* Ternary expression */
        struct {
            cfml_ast_node_t *condition;
            cfml_ast_node_t *true_branch;
            cfml_ast_node_t *false_branch;
        } ternary;
        
        /* Function call */
        struct {
            ngx_str_t       name;
            ngx_array_t     *args;      /* Array of cfml_ast_node_t* */
        } function_call;
        
        /* Method call */
        struct {
            cfml_ast_node_t *object;
            ngx_str_t       method_name;
            ngx_array_t     *args;
        } method_call;
        
        /* Array/struct access */
        struct {
            cfml_ast_node_t *base;
            cfml_ast_node_t *index;
        } access;
        
        /* Assignment */
        struct {
            cfml_ast_node_t *target;
            cfml_ast_node_t *value;
            cfml_binary_op_t compound_op;  /* For compound assignment */
        } assignment;
        
        /* Loop data */
        struct {
            cfml_loop_type_t loop_type;
            ngx_str_t       index_var;
            ngx_str_t       item_var;
            ngx_str_t       key_var;
        } loop;
        
        /* Text content */
        ngx_str_t           text;
    } data;
    
    ngx_pool_t          *pool;
};

/* Parsed template */
struct cfml_template_s {
    ngx_str_t           path;
    cfml_ast_node_t     *root;
    time_t              mtime;
    ngx_pool_t          *pool;
    unsigned            cached:1;
    unsigned            has_cfscript:1;
};

/* Execution context */
struct cfml_context_s {
    ngx_http_request_t  *r;
    ngx_pool_t          *pool;
    
    /* Output buffer */
    ngx_chain_t         *output_chain;
    ngx_chain_t         **output_last;
    ngx_buf_t           *current_buf;
    size_t              output_size;
    
    /* Variable scopes */
    cfml_scope_t        *scope_stack;
    cfml_struct_t       *variables_scope;
    cfml_struct_t       *local_scope;
    cfml_struct_t       *arguments_scope;
    cfml_struct_t       *url_scope;
    cfml_struct_t       *form_scope;
    cfml_struct_t       *cgi_scope;
    cfml_struct_t       *cookie_scope;
    cfml_struct_t       *request_scope;
    cfml_struct_t       *session_scope;
    cfml_struct_t       *application_scope;
    cfml_struct_t       *server_scope;
    
    /* Current execution state */
    cfml_template_t     *current_template;
    cfml_component_t    *current_component;
    cfml_function_t     *current_function;
    cfml_query_t        *current_query;
    
    /* Control flow */
    unsigned            abort:1;
    unsigned            exit:1;
    unsigned            return_:1;
    unsigned            break_:1;
    unsigned            continue_:1;
    cfml_value_t        *return_value;
    
    /* Error handling */
    ngx_str_t           error_message;
    ngx_uint_t          error_line;
    cfml_value_t        *exception;
    
    /* Settings */
    unsigned            enable_cfoutput_only:1;
    unsigned            request_timeout;
    unsigned            debug:1;
    
    /* Application.cfc */
    cfml_component_t    *application_cfc;
    
    /* Include depth (for recursion protection) */
    ngx_uint_t          include_depth;
    ngx_uint_t          max_include_depth;
    
    /* SaveContent buffer stack */
    ngx_array_t         *savecontent_stack;
    
    /* Transaction state */
    ngx_uint_t          transaction_depth;
    
    /* Thread state */
    ngx_array_t         *threads;
};

/* Configuration structures */
typedef struct {
    ngx_flag_t          enable;
    ngx_str_t           root;
    ngx_array_t         *index;         /* Index files */
    ngx_flag_t          cache;
    size_t              cache_size;
    ngx_str_t           fastcgi_pass;
    ngx_str_t           error_page;
    ngx_flag_t          strict_mode;
    ngx_msec_t          application_timeout;
    ngx_msec_t          session_timeout;
    ngx_msec_t          request_timeout;
    ngx_uint_t          max_include_depth;
    ngx_array_t         *datasources;
} ngx_http_cfml_loc_conf_t;

typedef struct {
    ngx_shm_zone_t      *session_zone;
    ngx_shm_zone_t      *application_zone;
    ngx_shm_zone_t      *cache_zone;
    ngx_hash_t          builtin_functions;
    ngx_array_t         *datasources;
} ngx_http_cfml_main_conf_t;

/* Datasource configuration */
typedef struct {
    ngx_str_t           name;
    ngx_str_t           driver;
    ngx_str_t           host;
    ngx_uint_t          port;
    ngx_str_t           database;
    ngx_str_t           username;
    ngx_str_t           password;
    ngx_str_t           connection_string;
    ngx_uint_t          pool_size;
} cfml_datasource_t;

/* Built-in function handler */
typedef cfml_value_t* (*cfml_builtin_func_t)(cfml_context_t *ctx, 
                                              ngx_array_t *args);

/* Built-in function definition */
typedef struct {
    ngx_str_t           name;
    cfml_builtin_func_t handler;
    ngx_int_t           min_args;
    ngx_int_t           max_args;
    ngx_str_t           description;
} cfml_builtin_def_t;

/* Error codes */
typedef enum {
    CFML_OK = 0,
    CFML_ERROR,
    CFML_ERROR_PARSE,
    CFML_ERROR_RUNTIME,
    CFML_ERROR_TYPE,
    CFML_ERROR_UNDEFINED,
    CFML_ERROR_NULL,
    CFML_ERROR_BOUNDS,
    CFML_ERROR_IO,
    CFML_ERROR_DATABASE,
    CFML_ERROR_TIMEOUT,
    CFML_ERROR_MEMORY,
    CFML_ERROR_SECURITY
} cfml_error_t;

#endif /* _CFML_TYPES_H_ */
