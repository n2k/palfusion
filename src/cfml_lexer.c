/*
 * CFML Lexer - Tokenizer implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_lexer.h"

/* Keyword table */
typedef struct {
    ngx_str_t           name;
    cfml_token_type_t   type;
} cfml_keyword_t;

static cfml_keyword_t cfml_keywords[] = {
    { ngx_string("var"), CFML_TOKEN_VAR },
    { ngx_string("if"), CFML_TOKEN_IF },
    { ngx_string("else"), CFML_TOKEN_ELSE },
    { ngx_string("for"), CFML_TOKEN_FOR },
    { ngx_string("in"), CFML_TOKEN_IN },
    { ngx_string("while"), CFML_TOKEN_WHILE },
    { ngx_string("do"), CFML_TOKEN_DO },
    { ngx_string("switch"), CFML_TOKEN_SWITCH },
    { ngx_string("case"), CFML_TOKEN_CASE },
    { ngx_string("default"), CFML_TOKEN_DEFAULT },
    { ngx_string("break"), CFML_TOKEN_BREAK },
    { ngx_string("continue"), CFML_TOKEN_CONTINUE },
    { ngx_string("return"), CFML_TOKEN_RETURN },
    { ngx_string("try"), CFML_TOKEN_TRY },
    { ngx_string("catch"), CFML_TOKEN_CATCH },
    { ngx_string("finally"), CFML_TOKEN_FINALLY },
    { ngx_string("throw"), CFML_TOKEN_THROW },
    { ngx_string("rethrow"), CFML_TOKEN_RETHROW },
    { ngx_string("function"), CFML_TOKEN_FUNCTION },
    { ngx_string("component"), CFML_TOKEN_COMPONENT },
    { ngx_string("interface"), CFML_TOKEN_INTERFACE },
    { ngx_string("property"), CFML_TOKEN_PROPERTY },
    { ngx_string("new"), CFML_TOKEN_NEW },
    { ngx_string("import"), CFML_TOKEN_IMPORT },
    { ngx_string("null"), CFML_TOKEN_NULL },
    { ngx_string("this"), CFML_TOKEN_THIS },
    { ngx_string("super"), CFML_TOKEN_SUPER },
    { ngx_string("true"), CFML_TOKEN_BOOLEAN_TRUE },
    { ngx_string("false"), CFML_TOKEN_BOOLEAN_FALSE },
    { ngx_string("yes"), CFML_TOKEN_BOOLEAN_TRUE },
    { ngx_string("no"), CFML_TOKEN_BOOLEAN_FALSE },
    { ngx_string("public"), CFML_TOKEN_PUBLIC },
    { ngx_string("private"), CFML_TOKEN_PRIVATE },
    { ngx_string("package"), CFML_TOKEN_PACKAGE },
    { ngx_string("remote"), CFML_TOKEN_REMOTE },
    { ngx_string("static"), CFML_TOKEN_STATIC },
    { ngx_string("final"), CFML_TOKEN_FINAL },
    { ngx_string("abstract"), CFML_TOKEN_ABSTRACT },
    /* Operators */
    { ngx_string("and"), CFML_TOKEN_AND },
    { ngx_string("or"), CFML_TOKEN_OR },
    { ngx_string("not"), CFML_TOKEN_NOT },
    { ngx_string("xor"), CFML_TOKEN_XOR },
    { ngx_string("eqv"), CFML_TOKEN_EQV },
    { ngx_string("imp"), CFML_TOKEN_IMP },
    { ngx_string("mod"), CFML_TOKEN_MOD },
    { ngx_string("eq"), CFML_TOKEN_EQ },
    { ngx_string("neq"), CFML_TOKEN_NEQ },
    { ngx_string("lt"), CFML_TOKEN_LT },
    { ngx_string("lte"), CFML_TOKEN_LTE },
    { ngx_string("le"), CFML_TOKEN_LTE },
    { ngx_string("gt"), CFML_TOKEN_GT },
    { ngx_string("gte"), CFML_TOKEN_GTE },
    { ngx_string("ge"), CFML_TOKEN_GTE },
    { ngx_string("is"), CFML_TOKEN_EQ },
    { ngx_string("contains"), CFML_TOKEN_CONTAINS },
    /* Types */
    { ngx_string("any"), CFML_TOKEN_TYPE_ANY },
    { ngx_string("array"), CFML_TOKEN_TYPE_ARRAY },
    { ngx_string("binary"), CFML_TOKEN_TYPE_BINARY },
    { ngx_string("boolean"), CFML_TOKEN_TYPE_BOOLEAN },
    { ngx_string("date"), CFML_TOKEN_TYPE_DATE },
    { ngx_string("guid"), CFML_TOKEN_TYPE_GUID },
    { ngx_string("numeric"), CFML_TOKEN_TYPE_NUMERIC },
    { ngx_string("query"), CFML_TOKEN_TYPE_QUERY },
    { ngx_string("string"), CFML_TOKEN_TYPE_STRING },
    { ngx_string("struct"), CFML_TOKEN_TYPE_STRUCT },
    { ngx_string("uuid"), CFML_TOKEN_TYPE_UUID },
    { ngx_string("void"), CFML_TOKEN_TYPE_VOID },
    { ngx_string("xml"), CFML_TOKEN_TYPE_XML },
    { ngx_null_string, 0 }
};

/* Scope names - use token type for table compatibility */
typedef struct {
    ngx_str_t           name;
    cfml_scope_type_t   scope;
} cfml_scope_keyword_t;

static cfml_scope_keyword_t cfml_scopes[] = {
    { ngx_string("variables"), CFML_SCOPE_VARIABLES },
    { ngx_string("local"), CFML_SCOPE_LOCAL },
    { ngx_string("arguments"), CFML_SCOPE_ARGUMENTS },
    { ngx_string("url"), CFML_SCOPE_URL },
    { ngx_string("form"), CFML_SCOPE_FORM },
    { ngx_string("cgi"), CFML_SCOPE_CGI },
    { ngx_string("cookie"), CFML_SCOPE_COOKIE },
    { ngx_string("request"), CFML_SCOPE_REQUEST },
    { ngx_string("session"), CFML_SCOPE_SESSION },
    { ngx_string("application"), CFML_SCOPE_APPLICATION },
    { ngx_string("server"), CFML_SCOPE_SERVER },
    { ngx_string("client"), CFML_SCOPE_CLIENT },
    { ngx_string("this"), CFML_SCOPE_THIS },
    { ngx_string("super"), CFML_SCOPE_SUPER },
    { ngx_string("caller"), CFML_SCOPE_CALLER },
    { ngx_string("attributes"), CFML_SCOPE_ATTRIBUTES },
    { ngx_string("thread"), CFML_SCOPE_THREAD },
    { ngx_string("cfthread"), CFML_SCOPE_CFTHREAD },
    { ngx_null_string, 0 }
};

/* Helper macros */
#define CFML_LEXER_CHAR(l) ((l)->pos < (l)->input_len ? (l)->input[(l)->pos] : '\0')
#define CFML_LEXER_PEEK(l, n) ((l)->pos + (n) < (l)->input_len ? (l)->input[(l)->pos + (n)] : '\0')
#define CFML_LEXER_ADVANCE(l) do { \
    if ((l)->input[(l)->pos] == '\n') { \
        (l)->line++; \
        (l)->column = 1; \
    } else { \
        (l)->column++; \
    } \
    (l)->pos++; \
} while (0)

/* Create a new token */
static cfml_token_t *
cfml_token_create(cfml_lexer_t *lexer, cfml_token_type_t type)
{
    cfml_token_t *token;

    token = ngx_palloc(lexer->pool, sizeof(cfml_token_t));
    if (token == NULL) {
        return NULL;
    }

    token->type = type;
    token->line = lexer->line;
    token->column = lexer->column;
    token->offset = lexer->pos;
    token->value.len = 0;
    token->value.data = NULL;

    return token;
}

/* Create lexer */
cfml_lexer_t *
cfml_lexer_create(ngx_pool_t *pool, u_char *input, size_t len)
{
    cfml_lexer_t *lexer;

    lexer = ngx_pcalloc(pool, sizeof(cfml_lexer_t));
    if (lexer == NULL) {
        return NULL;
    }

    lexer->pool = pool;
    lexer->input = input;
    lexer->input_len = len;
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->state = CFML_LEXER_STATE_TEXT;
    lexer->output_depth = 0;

    lexer->tokens = ngx_array_create(pool, 256, sizeof(cfml_token_t *));
    if (lexer->tokens == NULL) {
        return NULL;
    }

    return lexer;
}

/* Destroy lexer */
void
cfml_lexer_destroy(cfml_lexer_t *lexer)
{
    /* Pool-allocated, nothing to do */
}

/* Skip whitespace */
static void
cfml_lexer_skip_whitespace(cfml_lexer_t *lexer)
{
    while (lexer->pos < lexer->input_len) {
        u_char c = CFML_LEXER_CHAR(lexer);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            CFML_LEXER_ADVANCE(lexer);
        } else {
            break;
        }
    }
}

/* Check if character is identifier start */
static ngx_int_t
cfml_is_identifier_start(u_char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';
}

/* Check if character is identifier part */
static ngx_int_t
cfml_is_identifier_part(u_char c)
{
    return cfml_is_identifier_start(c) || (c >= '0' && c <= '9');
}

/* Check if character is digit */
static ngx_int_t
cfml_is_digit(u_char c)
{
    return c >= '0' && c <= '9';
}

/* Check if character is hex digit - currently unused but kept for future */
#if 0
static ngx_int_t
cfml_is_hex_digit(u_char c)
{
    return cfml_is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
#endif

/* Scan identifier */
static cfml_token_t *
cfml_lexer_scan_identifier(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start = lexer->pos;
    cfml_keyword_t *kw;

    while (lexer->pos < lexer->input_len && 
           cfml_is_identifier_part(CFML_LEXER_CHAR(lexer))) {
        CFML_LEXER_ADVANCE(lexer);
    }

    token = cfml_token_create(lexer, CFML_TOKEN_IDENTIFIER);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    /* Check if it's a keyword */
    for (kw = cfml_keywords; kw->name.len > 0; kw++) {
        if (token->value.len == kw->name.len &&
            ngx_strncasecmp(token->value.data, kw->name.data, kw->name.len) == 0) {
            token->type = kw->type;
            break;
        }
    }

    return token;
}

/* Scan number */
static cfml_token_t *
cfml_lexer_scan_number(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start = lexer->pos;
    ngx_int_t is_float = 0;

    /* Integer part */
    while (lexer->pos < lexer->input_len && cfml_is_digit(CFML_LEXER_CHAR(lexer))) {
        CFML_LEXER_ADVANCE(lexer);
    }

    /* Decimal part */
    if (CFML_LEXER_CHAR(lexer) == '.' && cfml_is_digit(CFML_LEXER_PEEK(lexer, 1))) {
        is_float = 1;
        CFML_LEXER_ADVANCE(lexer);
        while (lexer->pos < lexer->input_len && cfml_is_digit(CFML_LEXER_CHAR(lexer))) {
            CFML_LEXER_ADVANCE(lexer);
        }
    }

    /* Exponent part */
    if (CFML_LEXER_CHAR(lexer) == 'e' || CFML_LEXER_CHAR(lexer) == 'E') {
        is_float = 1;
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '+' || CFML_LEXER_CHAR(lexer) == '-') {
            CFML_LEXER_ADVANCE(lexer);
        }
        while (lexer->pos < lexer->input_len && cfml_is_digit(CFML_LEXER_CHAR(lexer))) {
            CFML_LEXER_ADVANCE(lexer);
        }
    }

    token = cfml_token_create(lexer, is_float ? CFML_TOKEN_FLOAT : CFML_TOKEN_INTEGER);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    return token;
}

/* Scan string */
static cfml_token_t *
cfml_lexer_scan_string(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start;
    u_char quote = CFML_LEXER_CHAR(lexer);

    CFML_LEXER_ADVANCE(lexer);  /* Skip opening quote */
    start = lexer->pos;

    while (lexer->pos < lexer->input_len) {
        u_char c = CFML_LEXER_CHAR(lexer);
        
        if (c == quote) {
            /* Check for escaped quote */
            if (CFML_LEXER_PEEK(lexer, 1) == quote) {
                CFML_LEXER_ADVANCE(lexer);
                CFML_LEXER_ADVANCE(lexer);
                continue;
            }
            break;
        }
        
        if (c == '\\') {
            /* Escape sequence */
            CFML_LEXER_ADVANCE(lexer);
            if (lexer->pos < lexer->input_len) {
                CFML_LEXER_ADVANCE(lexer);
            }
            continue;
        }
        
        CFML_LEXER_ADVANCE(lexer);
    }

    token = cfml_token_create(lexer, CFML_TOKEN_STRING);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    if (CFML_LEXER_CHAR(lexer) == quote) {
        CFML_LEXER_ADVANCE(lexer);  /* Skip closing quote */
    }

    return token;
}

/* Scan CFML comment */
static cfml_token_t *
cfml_lexer_scan_cfml_comment(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start = lexer->pos;
    ngx_int_t depth = 1;

    /* Skip <!--- */
    lexer->pos += 4;
    lexer->column += 4;

    while (lexer->pos < lexer->input_len && depth > 0) {
        if (lexer->pos + 3 < lexer->input_len &&
            lexer->input[lexer->pos] == '-' &&
            lexer->input[lexer->pos + 1] == '-' &&
            lexer->input[lexer->pos + 2] == '-' &&
            lexer->input[lexer->pos + 3] == '>') {
            depth--;
            if (depth == 0) {
                lexer->pos += 4;
                lexer->column += 4;
                break;
            }
        }
        
        if (lexer->pos + 3 < lexer->input_len &&
            lexer->input[lexer->pos] == '<' &&
            lexer->input[lexer->pos + 1] == '!' &&
            lexer->input[lexer->pos + 2] == '-' &&
            lexer->input[lexer->pos + 3] == '-' &&
            lexer->input[lexer->pos + 4] == '-') {
            depth++;
        }
        
        CFML_LEXER_ADVANCE(lexer);
    }

    token = cfml_token_create(lexer, CFML_TOKEN_COMMENT);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    return token;
}

/* Scan CF tag */
static cfml_token_t *
cfml_lexer_scan_cf_tag(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start;

    CFML_LEXER_ADVANCE(lexer);  /* Skip < */
    
    if (CFML_LEXER_CHAR(lexer) == '/') {
        CFML_LEXER_ADVANCE(lexer);
    }

    /* Skip 'cf' prefix */
    CFML_LEXER_ADVANCE(lexer);
    CFML_LEXER_ADVANCE(lexer);

    start = lexer->pos;

    /* Read tag name */
    while (lexer->pos < lexer->input_len && 
           cfml_is_identifier_part(CFML_LEXER_CHAR(lexer))) {
        CFML_LEXER_ADVANCE(lexer);
    }

    token = cfml_token_create(lexer, CFML_TOKEN_CF_TAG_NAME);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    lexer->state = CFML_LEXER_STATE_TAG;

    return token;
}

/* Scan text content */
static cfml_token_t *
cfml_lexer_scan_text(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    size_t start = lexer->pos;

    while (lexer->pos < lexer->input_len) {
        u_char c = CFML_LEXER_CHAR(lexer);
        
        /* Check for CF tag start */
        if (c == '<') {
            if (lexer->pos + 2 < lexer->input_len) {
                u_char c1 = CFML_LEXER_PEEK(lexer, 1);
                u_char c2 = CFML_LEXER_PEEK(lexer, 2);
                
                /* <cf or </cf */
                if ((c1 == 'c' || c1 == 'C') && (c2 == 'f' || c2 == 'F')) {
                    break;
                }
                if (c1 == '/' && 
                    (CFML_LEXER_PEEK(lexer, 2) == 'c' || CFML_LEXER_PEEK(lexer, 2) == 'C') &&
                    (CFML_LEXER_PEEK(lexer, 3) == 'f' || CFML_LEXER_PEEK(lexer, 3) == 'F')) {
                    break;
                }
                
                /* CFML comment <!--- */
                if (c1 == '!' && c2 == '-' && 
                    CFML_LEXER_PEEK(lexer, 3) == '-' && 
                    CFML_LEXER_PEEK(lexer, 4) == '-') {
                    break;
                }
            }
        }
        
        /* Check for hash expression in cfoutput */
        if (c == '#' && lexer->output_depth > 0) {
            if (CFML_LEXER_PEEK(lexer, 1) != '#') {
                break;
            }
            /* Escaped hash ## */
            CFML_LEXER_ADVANCE(lexer);
        }
        
        CFML_LEXER_ADVANCE(lexer);
    }

    if (lexer->pos == start) {
        return NULL;
    }

    token = cfml_token_create(lexer, CFML_TOKEN_TEXT);
    if (token == NULL) {
        return NULL;
    }

    token->value.data = lexer->input + start;
    token->value.len = lexer->pos - start;

    return token;
}

/* Get next token in expression mode */
static cfml_token_t *
cfml_lexer_next_expression_token(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    u_char c;

    cfml_lexer_skip_whitespace(lexer);

    if (lexer->pos >= lexer->input_len) {
        return cfml_token_create(lexer, CFML_TOKEN_EOF);
    }

    c = CFML_LEXER_CHAR(lexer);

    /* Check for end of expression (hash in cfoutput context) */
    if (c == '#' && lexer->state == CFML_LEXER_STATE_EXPRESSION) {
        token = cfml_token_create(lexer, CFML_TOKEN_HASH_CLOSE);
        CFML_LEXER_ADVANCE(lexer);
        lexer->state = CFML_LEXER_STATE_OUTPUT;
        return token;
    }

    /* Identifier */
    if (cfml_is_identifier_start(c)) {
        return cfml_lexer_scan_identifier(lexer);
    }

    /* Number */
    if (cfml_is_digit(c) || (c == '.' && cfml_is_digit(CFML_LEXER_PEEK(lexer, 1)))) {
        return cfml_lexer_scan_number(lexer);
    }

    /* String */
    if (c == '"' || c == '\'') {
        return cfml_lexer_scan_string(lexer);
    }

    /* Operators and punctuation */
    token = cfml_token_create(lexer, CFML_TOKEN_ERROR);
    if (token == NULL) {
        return NULL;
    }

    switch (c) {
    case '+':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '+') {
            token->type = CFML_TOKEN_INCREMENT;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_PLUS_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_PLUS;
        }
        break;

    case '-':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '-') {
            token->type = CFML_TOKEN_DECREMENT;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_MINUS_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '>') {
            token->type = CFML_TOKEN_ARROW;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_MINUS;
        }
        break;

    case '*':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_MUL_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_MULTIPLY;
        }
        break;

    case '/':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_DIV_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_DIVIDE;
        }
        break;

    case '%':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_MOD_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_MOD;
        }
        break;

    case '^':
        token->type = CFML_TOKEN_POWER;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '\\':
        token->type = CFML_TOKEN_BACKSLASH;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '&':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '&') {
            token->type = CFML_TOKEN_AND;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_CONCAT_ASSIGN;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_CONCAT;
        }
        break;

    case '|':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '|') {
            token->type = CFML_TOKEN_OR;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_BITOR;
        }
        break;

    case '!':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_NEQ;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_NOT;
        }
        break;

    case '=':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_EQ;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '>') {
            token->type = CFML_TOKEN_FAT_ARROW;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_ASSIGN;
        }
        break;

    case '<':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_LTE;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '>') {
            token->type = CFML_TOKEN_NEQ;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_LT;
        }
        break;

    case '>':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == '=') {
            token->type = CFML_TOKEN_GTE;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_GT;
        }
        break;

    case '(':
        token->type = CFML_TOKEN_LPAREN;
        lexer->paren_depth++;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case ')':
        token->type = CFML_TOKEN_RPAREN;
        if (lexer->paren_depth > 0) {
            lexer->paren_depth--;
        }
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '[':
        token->type = CFML_TOKEN_LBRACKET;
        lexer->bracket_depth++;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case ']':
        token->type = CFML_TOKEN_RBRACKET;
        if (lexer->bracket_depth > 0) {
            lexer->bracket_depth--;
        }
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '{':
        token->type = CFML_TOKEN_LBRACE;
        lexer->brace_depth++;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '}':
        token->type = CFML_TOKEN_RBRACE;
        if (lexer->brace_depth > 0) {
            lexer->brace_depth--;
        }
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '.':
        token->type = CFML_TOKEN_DOT;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case ',':
        token->type = CFML_TOKEN_COMMA;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case ':':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == ':') {
            /* Scope resolution - treat as two colons */
            token->type = CFML_TOKEN_COLON;
        } else {
            token->type = CFML_TOKEN_COLON;
        }
        break;

    case ';':
        token->type = CFML_TOKEN_SEMICOLON;
        CFML_LEXER_ADVANCE(lexer);
        break;

    case '?':
        CFML_LEXER_ADVANCE(lexer);
        if (CFML_LEXER_CHAR(lexer) == ':') {
            token->type = CFML_TOKEN_ELVIS;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '?') {
            token->type = CFML_TOKEN_NULLCOALESCE;
            CFML_LEXER_ADVANCE(lexer);
        } else if (CFML_LEXER_CHAR(lexer) == '.') {
            token->type = CFML_TOKEN_SAFENAV;
            CFML_LEXER_ADVANCE(lexer);
        } else {
            token->type = CFML_TOKEN_QUESTION;
        }
        break;

    default:
        /* Unknown character */
        token->type = CFML_TOKEN_ERROR;
        token->value.data = lexer->input + lexer->pos;
        token->value.len = 1;
        CFML_LEXER_ADVANCE(lexer);
        break;
    }

    return token;
}

/* Get next token */
cfml_token_t *
cfml_lexer_next_token(cfml_lexer_t *lexer)
{
    cfml_token_t *token;
    u_char c;

    if (lexer->pos >= lexer->input_len) {
        return cfml_token_create(lexer, CFML_TOKEN_EOF);
    }

    /* Handle different lexer states */
    switch (lexer->state) {
    case CFML_LEXER_STATE_EXPRESSION:
    case CFML_LEXER_STATE_SCRIPT:
        return cfml_lexer_next_expression_token(lexer);

    case CFML_LEXER_STATE_TAG:
        cfml_lexer_skip_whitespace(lexer);
        c = CFML_LEXER_CHAR(lexer);
        
        /* End of tag */
        if (c == '>') {
            token = cfml_token_create(lexer, CFML_TOKEN_TAG_CLOSE);
            CFML_LEXER_ADVANCE(lexer);
            lexer->state = CFML_LEXER_STATE_TEXT;
            return token;
        }
        
        /* Self-closing tag */
        if (c == '/' && CFML_LEXER_PEEK(lexer, 1) == '>') {
            token = cfml_token_create(lexer, CFML_TOKEN_TAG_SELF_CLOSE);
            CFML_LEXER_ADVANCE(lexer);
            CFML_LEXER_ADVANCE(lexer);
            lexer->state = CFML_LEXER_STATE_TEXT;
            return token;
        }
        
        /* Attribute name */
        if (cfml_is_identifier_start(c)) {
            return cfml_lexer_scan_identifier(lexer);
        }
        
        /* = for attribute value */
        if (c == '=') {
            token = cfml_token_create(lexer, CFML_TOKEN_ASSIGN);
            CFML_LEXER_ADVANCE(lexer);
            return token;
        }
        
        /* Attribute value (string) */
        if (c == '"' || c == '\'') {
            return cfml_lexer_scan_string(lexer);
        }
        
        /* Unexpected character in tag */
        token = cfml_token_create(lexer, CFML_TOKEN_ERROR);
        token->value.data = lexer->input + lexer->pos;
        token->value.len = 1;
        CFML_LEXER_ADVANCE(lexer);
        return token;

    case CFML_LEXER_STATE_OUTPUT:
        c = CFML_LEXER_CHAR(lexer);
        
        /* Start of expression */
        if (c == '#') {
            token = cfml_token_create(lexer, CFML_TOKEN_HASH_OPEN);
            CFML_LEXER_ADVANCE(lexer);
            lexer->state = CFML_LEXER_STATE_EXPRESSION;
            return token;
        }
        
        /* Fall through to text mode for other content */
        /* fall through */

    case CFML_LEXER_STATE_TEXT:
    default:
        c = CFML_LEXER_CHAR(lexer);

        /* CFML comment */
        if (c == '<' && lexer->pos + 4 < lexer->input_len &&
            lexer->input[lexer->pos + 1] == '!' &&
            lexer->input[lexer->pos + 2] == '-' &&
            lexer->input[lexer->pos + 3] == '-' &&
            lexer->input[lexer->pos + 4] == '-') {
            return cfml_lexer_scan_cfml_comment(lexer);
        }

        /* CF tag */
        if (c == '<') {
            u_char c1 = CFML_LEXER_PEEK(lexer, 1);
            u_char c2 = CFML_LEXER_PEEK(lexer, 2);
            
            if ((c1 == 'c' || c1 == 'C') && (c2 == 'f' || c2 == 'F')) {
                return cfml_lexer_scan_cf_tag(lexer);
            }
            
            if (c1 == '/' &&
                (CFML_LEXER_PEEK(lexer, 2) == 'c' || CFML_LEXER_PEEK(lexer, 2) == 'C') &&
                (CFML_LEXER_PEEK(lexer, 3) == 'f' || CFML_LEXER_PEEK(lexer, 3) == 'F')) {
                token = cfml_token_create(lexer, CFML_TOKEN_TAG_END_OPEN);
                CFML_LEXER_ADVANCE(lexer);  /* < */
                CFML_LEXER_ADVANCE(lexer);  /* / */
                return token;
            }
        }

        /* Text content */
        return cfml_lexer_scan_text(lexer);
    }
}

/* Peek at next token without consuming */
cfml_token_t *
cfml_lexer_peek_token(cfml_lexer_t *lexer)
{
    size_t saved_pos = lexer->pos;
    ngx_uint_t saved_line = lexer->line;
    ngx_uint_t saved_column = lexer->column;
    cfml_lexer_state_t saved_state = lexer->state;

    cfml_token_t *token = cfml_lexer_next_token(lexer);

    lexer->pos = saved_pos;
    lexer->line = saved_line;
    lexer->column = saved_column;
    lexer->state = saved_state;

    return token;
}

/* Check if identifier is a keyword */
ngx_int_t
cfml_is_keyword(ngx_str_t *str, cfml_token_type_t *type)
{
    cfml_keyword_t *kw;

    for (kw = cfml_keywords; kw->name.len > 0; kw++) {
        if (str->len == kw->name.len &&
            ngx_strncasecmp(str->data, kw->name.data, kw->name.len) == 0) {
            *type = kw->type;
            return 1;
        }
    }

    return 0;
}

/* Check if identifier is a scope name */
ngx_int_t
cfml_is_scope_name(ngx_str_t *str, cfml_scope_type_t *scope)
{
    cfml_scope_keyword_t *s;

    for (s = cfml_scopes; s->name.len > 0; s++) {
        if (str->len == s->name.len &&
            ngx_strncasecmp(str->data, s->name.data, s->name.len) == 0) {
            *scope = s->scope;
            return 1;
        }
    }

    return 0;
}

/* Get token type name for debugging */
const char *
cfml_token_type_name(cfml_token_type_t type)
{
    static const char *names[] = {
        "EOF", "ERROR",
        "TEXT", "STRING", "NUMBER", "INTEGER", "FLOAT", "TRUE", "FALSE",
        "IDENTIFIER", "SCOPE",
        "TAG_OPEN", "TAG_CLOSE", "TAG_SELF_CLOSE", "TAG_END_OPEN", "CF_TAG_NAME",
        "ATTRIBUTE_NAME", "ATTRIBUTE_VALUE",
        "HASH_OPEN", "HASH_CLOSE", "OUTPUT_START", "OUTPUT_END",
        "SCRIPT_START", "SCRIPT_END", "SCRIPT_CONTENT",
        "COMMENT", "HTML_COMMENT",
        /* ... more would be added */
    };

    if ((size_t)type < sizeof(names) / sizeof(names[0])) {
        return names[type];
    }

    return "UNKNOWN";
}
