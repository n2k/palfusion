/*
 * CFML Lexer - Tokenizer for CFML source code
 */

#ifndef _CFML_LEXER_H_
#define _CFML_LEXER_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Token types */
typedef enum {
    /* Special */
    CFML_TOKEN_EOF = 0,
    CFML_TOKEN_ERROR,
    
    /* Literals */
    CFML_TOKEN_TEXT,
    CFML_TOKEN_STRING,
    CFML_TOKEN_NUMBER,
    CFML_TOKEN_INTEGER,
    CFML_TOKEN_FLOAT,
    CFML_TOKEN_BOOLEAN_TRUE,
    CFML_TOKEN_BOOLEAN_FALSE,
    
    /* Identifiers */
    CFML_TOKEN_IDENTIFIER,
    CFML_TOKEN_SCOPE,
    
    /* Tags */
    CFML_TOKEN_TAG_OPEN,          /* < */
    CFML_TOKEN_TAG_CLOSE,         /* > */
    CFML_TOKEN_TAG_SELF_CLOSE,    /* /> */
    CFML_TOKEN_TAG_END_OPEN,      /* </ */
    CFML_TOKEN_CF_TAG_NAME,       /* cf... */
    CFML_TOKEN_ATTRIBUTE_NAME,
    CFML_TOKEN_ATTRIBUTE_VALUE,
    
    /* Output expressions */
    CFML_TOKEN_HASH_OPEN,         /* # at start of expression */
    CFML_TOKEN_HASH_CLOSE,        /* # at end of expression */
    CFML_TOKEN_OUTPUT_START,      /* <cfoutput> */
    CFML_TOKEN_OUTPUT_END,        /* </cfoutput> */
    
    /* CFScript */
    CFML_TOKEN_SCRIPT_START,      /* <cfscript> */
    CFML_TOKEN_SCRIPT_END,        /* </cfscript> */
    CFML_TOKEN_SCRIPT_CONTENT,
    
    /* Comments */
    CFML_TOKEN_COMMENT,           /* <!--- ---> */
    CFML_TOKEN_HTML_COMMENT,      /* <!-- --> */
    
    /* Operators */
    CFML_TOKEN_PLUS,              /* + */
    CFML_TOKEN_MINUS,             /* - */
    CFML_TOKEN_MULTIPLY,          /* * */
    CFML_TOKEN_DIVIDE,            /* / */
    CFML_TOKEN_MOD,               /* % or mod */
    CFML_TOKEN_POWER,             /* ^ */
    CFML_TOKEN_BACKSLASH,         /* \ (integer division) */
    CFML_TOKEN_CONCAT,            /* & */
    
    /* Comparison */
    CFML_TOKEN_EQ,                /* = or eq or is */
    CFML_TOKEN_NEQ,               /* != or <> or neq */
    CFML_TOKEN_LT,                /* < or lt */
    CFML_TOKEN_LTE,               /* <= or lte */
    CFML_TOKEN_GT,                /* > or gt */
    CFML_TOKEN_GTE,               /* >= or gte */
    
    /* Logical */
    CFML_TOKEN_AND,               /* && or and */
    CFML_TOKEN_OR,                /* || or or */
    CFML_TOKEN_NOT,               /* ! or not */
    CFML_TOKEN_XOR,               /* xor */
    CFML_TOKEN_EQV,               /* eqv */
    CFML_TOKEN_IMP,               /* imp */
    
    /* String operators */
    CFML_TOKEN_CONTAINS,          /* contains */
    CFML_TOKEN_NOT_CONTAINS,      /* does not contain */
    
    /* Bitwise */
    CFML_TOKEN_BITAND,
    CFML_TOKEN_BITOR,
    CFML_TOKEN_BITNOT,
    CFML_TOKEN_BITXOR,
    
    /* Assignment */
    CFML_TOKEN_ASSIGN,            /* = */
    CFML_TOKEN_PLUS_ASSIGN,       /* += */
    CFML_TOKEN_MINUS_ASSIGN,      /* -= */
    CFML_TOKEN_MUL_ASSIGN,        /* *= */
    CFML_TOKEN_DIV_ASSIGN,        /* /= */
    CFML_TOKEN_MOD_ASSIGN,        /* %= */
    CFML_TOKEN_CONCAT_ASSIGN,     /* &= */
    CFML_TOKEN_INCREMENT,         /* ++ */
    CFML_TOKEN_DECREMENT,         /* -- */
    
    /* Punctuation */
    CFML_TOKEN_LPAREN,            /* ( */
    CFML_TOKEN_RPAREN,            /* ) */
    CFML_TOKEN_LBRACKET,          /* [ */
    CFML_TOKEN_RBRACKET,          /* ] */
    CFML_TOKEN_LBRACE,            /* { */
    CFML_TOKEN_RBRACE,            /* } */
    CFML_TOKEN_DOT,               /* . */
    CFML_TOKEN_COMMA,             /* , */
    CFML_TOKEN_COLON,             /* : */
    CFML_TOKEN_SEMICOLON,         /* ; */
    CFML_TOKEN_QUESTION,          /* ? */
    CFML_TOKEN_ELVIS,             /* ?: */
    CFML_TOKEN_NULLCOALESCE,      /* ?? */
    CFML_TOKEN_SAFENAV,           /* ?. */
    CFML_TOKEN_ARROW,             /* -> */
    CFML_TOKEN_FAT_ARROW,         /* => */
    
    /* Keywords (CFScript) */
    CFML_TOKEN_VAR,
    CFML_TOKEN_IF,
    CFML_TOKEN_ELSE,
    CFML_TOKEN_FOR,
    CFML_TOKEN_IN,
    CFML_TOKEN_WHILE,
    CFML_TOKEN_DO,
    CFML_TOKEN_SWITCH,
    CFML_TOKEN_CASE,
    CFML_TOKEN_DEFAULT,
    CFML_TOKEN_BREAK,
    CFML_TOKEN_CONTINUE,
    CFML_TOKEN_RETURN,
    CFML_TOKEN_TRY,
    CFML_TOKEN_CATCH,
    CFML_TOKEN_FINALLY,
    CFML_TOKEN_THROW,
    CFML_TOKEN_RETHROW,
    CFML_TOKEN_FUNCTION,
    CFML_TOKEN_COMPONENT,
    CFML_TOKEN_INTERFACE,
    CFML_TOKEN_PROPERTY,
    CFML_TOKEN_NEW,
    CFML_TOKEN_IMPORT,
    CFML_TOKEN_NULL,
    CFML_TOKEN_THIS,
    CFML_TOKEN_SUPER,
    
    /* Access modifiers */
    CFML_TOKEN_PUBLIC,
    CFML_TOKEN_PRIVATE,
    CFML_TOKEN_PACKAGE,
    CFML_TOKEN_REMOTE,
    CFML_TOKEN_STATIC,
    CFML_TOKEN_FINAL,
    CFML_TOKEN_ABSTRACT,
    
    /* Types */
    CFML_TOKEN_TYPE_ANY,
    CFML_TOKEN_TYPE_ARRAY,
    CFML_TOKEN_TYPE_BINARY,
    CFML_TOKEN_TYPE_BOOLEAN,
    CFML_TOKEN_TYPE_DATE,
    CFML_TOKEN_TYPE_FUNCTION,
    CFML_TOKEN_TYPE_GUID,
    CFML_TOKEN_TYPE_NUMERIC,
    CFML_TOKEN_TYPE_QUERY,
    CFML_TOKEN_TYPE_STRING,
    CFML_TOKEN_TYPE_STRUCT,
    CFML_TOKEN_TYPE_UUID,
    CFML_TOKEN_TYPE_VOID,
    CFML_TOKEN_TYPE_XML
} cfml_token_type_t;

/* Token structure */
typedef struct {
    cfml_token_type_t   type;
    ngx_str_t           value;
    ngx_uint_t          line;
    ngx_uint_t          column;
    ngx_uint_t          offset;
} cfml_token_t;

/* Lexer state */
typedef enum {
    CFML_LEXER_STATE_TEXT = 0,
    CFML_LEXER_STATE_TAG,
    CFML_LEXER_STATE_TAG_NAME,
    CFML_LEXER_STATE_ATTR_NAME,
    CFML_LEXER_STATE_ATTR_VALUE,
    CFML_LEXER_STATE_SCRIPT,
    CFML_LEXER_STATE_OUTPUT,
    CFML_LEXER_STATE_EXPRESSION,
    CFML_LEXER_STATE_COMMENT
} cfml_lexer_state_t;

/* Lexer context */
typedef struct {
    u_char              *input;
    size_t              input_len;
    size_t              pos;
    ngx_uint_t          line;
    ngx_uint_t          column;
    cfml_lexer_state_t  state;
    ngx_uint_t          output_depth;     /* Nested cfoutput depth */
    ngx_uint_t          paren_depth;
    ngx_uint_t          bracket_depth;
    ngx_uint_t          brace_depth;
    ngx_pool_t          *pool;
    ngx_array_t         *tokens;          /* Pre-tokenized list */
    ngx_uint_t          token_pos;
    ngx_str_t           error;
} cfml_lexer_t;

/* Function prototypes */
cfml_lexer_t *cfml_lexer_create(ngx_pool_t *pool, u_char *input, size_t len);
void cfml_lexer_destroy(cfml_lexer_t *lexer);

cfml_token_t *cfml_lexer_next_token(cfml_lexer_t *lexer);
cfml_token_t *cfml_lexer_peek_token(cfml_lexer_t *lexer);
cfml_token_t *cfml_lexer_peek_ahead(cfml_lexer_t *lexer, ngx_uint_t n);
void cfml_lexer_push_back(cfml_lexer_t *lexer, cfml_token_t *token);

ngx_int_t cfml_lexer_tokenize_all(cfml_lexer_t *lexer);

/* State management */
void cfml_lexer_push_state(cfml_lexer_t *lexer, cfml_lexer_state_t state);
void cfml_lexer_pop_state(cfml_lexer_t *lexer);

/* Helper functions */
ngx_int_t cfml_is_keyword(ngx_str_t *str, cfml_token_type_t *type);
ngx_int_t cfml_is_type_keyword(ngx_str_t *str);
ngx_int_t cfml_is_scope_name(ngx_str_t *str, cfml_scope_type_t *scope);
const char *cfml_token_type_name(cfml_token_type_t type);

#endif /* _CFML_LEXER_H_ */
