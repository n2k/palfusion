/*
 * CFML CFScript - Full CFScript language support
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_cfscript.h"
#include "cfml_runtime.h"
#include "cfml_variables.h"
#include "cfml_expression.h"

/* Keyword table */
static struct {
    ngx_str_t name;
    cfscript_token_type_t type;
} cfscript_keywords[] = {
    { ngx_string("component"), CFSCRIPT_KW_COMPONENT },
    { ngx_string("interface"), CFSCRIPT_KW_INTERFACE },
    { ngx_string("function"), CFSCRIPT_KW_FUNCTION },
    { ngx_string("public"), CFSCRIPT_KW_PUBLIC },
    { ngx_string("private"), CFSCRIPT_KW_PRIVATE },
    { ngx_string("remote"), CFSCRIPT_KW_REMOTE },
    { ngx_string("package"), CFSCRIPT_KW_PACKAGE },
    { ngx_string("static"), CFSCRIPT_KW_STATIC },
    { ngx_string("final"), CFSCRIPT_KW_FINAL },
    { ngx_string("abstract"), CFSCRIPT_KW_ABSTRACT },
    { ngx_string("var"), CFSCRIPT_KW_VAR },
    { ngx_string("local"), CFSCRIPT_KW_LOCAL },
    { ngx_string("if"), CFSCRIPT_KW_IF },
    { ngx_string("else"), CFSCRIPT_KW_ELSE },
    { ngx_string("switch"), CFSCRIPT_KW_SWITCH },
    { ngx_string("case"), CFSCRIPT_KW_CASE },
    { ngx_string("default"), CFSCRIPT_KW_DEFAULT },
    { ngx_string("for"), CFSCRIPT_KW_FOR },
    { ngx_string("while"), CFSCRIPT_KW_WHILE },
    { ngx_string("do"), CFSCRIPT_KW_DO },
    { ngx_string("in"), CFSCRIPT_KW_IN },
    { ngx_string("break"), CFSCRIPT_KW_BREAK },
    { ngx_string("continue"), CFSCRIPT_KW_CONTINUE },
    { ngx_string("return"), CFSCRIPT_KW_RETURN },
    { ngx_string("try"), CFSCRIPT_KW_TRY },
    { ngx_string("catch"), CFSCRIPT_KW_CATCH },
    { ngx_string("finally"), CFSCRIPT_KW_FINALLY },
    { ngx_string("throw"), CFSCRIPT_KW_THROW },
    { ngx_string("rethrow"), CFSCRIPT_KW_RETHROW },
    { ngx_string("new"), CFSCRIPT_KW_NEW },
    { ngx_string("import"), CFSCRIPT_KW_IMPORT },
    { ngx_string("required"), CFSCRIPT_KW_REQUIRED },
    { ngx_string("param"), CFSCRIPT_KW_PARAM },
    { ngx_string("property"), CFSCRIPT_KW_PROPERTY },
    { ngx_string("include"), CFSCRIPT_KW_INCLUDE },
    { ngx_string("abort"), CFSCRIPT_KW_ABORT },
    { ngx_string("exit"), CFSCRIPT_KW_EXIT },
    { ngx_string("lock"), CFSCRIPT_KW_LOCK },
    { ngx_string("thread"), CFSCRIPT_KW_THREAD },
    { ngx_string("transaction"), CFSCRIPT_KW_TRANSACTION },
    { ngx_string("savecontent"), CFSCRIPT_KW_SAVECONTENT },
    { ngx_string("true"), CFSCRIPT_KW_TRUE },
    { ngx_string("false"), CFSCRIPT_KW_FALSE },
    { ngx_string("null"), CFSCRIPT_KW_NULL },
    { ngx_string("any"), CFSCRIPT_TYPE_ANY },
    { ngx_string("array"), CFSCRIPT_TYPE_ARRAY },
    { ngx_string("binary"), CFSCRIPT_TYPE_BINARY },
    { ngx_string("boolean"), CFSCRIPT_TYPE_BOOLEAN },
    { ngx_string("date"), CFSCRIPT_TYPE_DATE },
    { ngx_string("guid"), CFSCRIPT_TYPE_GUID },
    { ngx_string("numeric"), CFSCRIPT_TYPE_NUMERIC },
    { ngx_string("query"), CFSCRIPT_TYPE_QUERY },
    { ngx_string("string"), CFSCRIPT_TYPE_STRING },
    { ngx_string("struct"), CFSCRIPT_TYPE_STRUCT },
    { ngx_string("uuid"), CFSCRIPT_TYPE_UUID },
    { ngx_string("void"), CFSCRIPT_TYPE_VOID },
    { ngx_string("xml"), CFSCRIPT_TYPE_XML },
    { ngx_null_string, 0 }
};

static cfscript_token_type_t
cfscript_lookup_keyword(ngx_str_t *name)
{
    ngx_uint_t i;
    
    for (i = 0; cfscript_keywords[i].name.len > 0; i++) {
        if (name->len == cfscript_keywords[i].name.len &&
            ngx_strncasecmp(name->data, cfscript_keywords[i].name.data, name->len) == 0) {
            return cfscript_keywords[i].type;
        }
    }
    
    return CFSCRIPT_IDENTIFIER;
}

/* Lexer implementation */
cfscript_lexer_t *
cfscript_lexer_create(ngx_pool_t *pool, u_char *input, size_t len)
{
    cfscript_lexer_t *lexer;
    
    lexer = ngx_pcalloc(pool, sizeof(cfscript_lexer_t));
    if (lexer == NULL) {
        return NULL;
    }
    
    lexer->start = input;
    lexer->end = input + len;
    lexer->pos = input;
    lexer->line = 1;
    lexer->column = 1;
    lexer->pool = pool;
    
    return lexer;
}

static cfscript_token_t *
cfscript_token_create(cfscript_lexer_t *lexer, cfscript_token_type_t type)
{
    cfscript_token_t *token;
    
    token = ngx_pcalloc(lexer->pool, sizeof(cfscript_token_t));
    if (token == NULL) {
        return NULL;
    }
    
    token->type = type;
    token->line = lexer->line;
    token->column = lexer->column;
    
    return token;
}

static void
cfscript_skip_whitespace(cfscript_lexer_t *lexer)
{
    while (lexer->pos < lexer->end) {
        if (*lexer->pos == ' ' || *lexer->pos == '\t' || *lexer->pos == '\r') {
            lexer->pos++;
            lexer->column++;
        } else if (*lexer->pos == '\n') {
            lexer->pos++;
            lexer->line++;
            lexer->column = 1;
        } else {
            break;
        }
    }
}

static void
cfscript_skip_comment(cfscript_lexer_t *lexer)
{
    if (lexer->pos + 1 < lexer->end) {
        if (*lexer->pos == '/' && *(lexer->pos + 1) == '/') {
            /* Single-line comment */
            lexer->pos += 2;
            while (lexer->pos < lexer->end && *lexer->pos != '\n') {
                lexer->pos++;
            }
        } else if (*lexer->pos == '/' && *(lexer->pos + 1) == '*') {
            /* Multi-line comment */
            lexer->pos += 2;
            while (lexer->pos + 1 < lexer->end) {
                if (*lexer->pos == '*' && *(lexer->pos + 1) == '/') {
                    lexer->pos += 2;
                    break;
                }
                if (*lexer->pos == '\n') {
                    lexer->line++;
                    lexer->column = 1;
                }
                lexer->pos++;
            }
        }
    }
}

static cfscript_token_t *
cfscript_scan_string(cfscript_lexer_t *lexer)
{
    cfscript_token_t *token;
    u_char quote = *lexer->pos;
    u_char *start;
    
    lexer->pos++;
    start = lexer->pos;
    
    while (lexer->pos < lexer->end) {
        if (*lexer->pos == quote) {
            if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == quote) {
                /* Escaped quote */
                lexer->pos += 2;
                continue;
            }
            break;
        }
        if (*lexer->pos == '\n') {
            lexer->line++;
            lexer->column = 1;
        }
        lexer->pos++;
    }
    
    token = cfscript_token_create(lexer, CFSCRIPT_STRING);
    if (token != NULL) {
        token->value.data = start;
        token->value.len = lexer->pos - start;
    }
    
    if (lexer->pos < lexer->end) {
        lexer->pos++;  /* Skip closing quote */
    }
    
    return token;
}

static cfscript_token_t *
cfscript_scan_number(cfscript_lexer_t *lexer)
{
    cfscript_token_t *token;
    u_char *start = lexer->pos;
    
    while (lexer->pos < lexer->end && 
           ((*lexer->pos >= '0' && *lexer->pos <= '9') || *lexer->pos == '.')) {
        lexer->pos++;
    }
    
    /* Check for scientific notation */
    if (lexer->pos < lexer->end && (*lexer->pos == 'e' || *lexer->pos == 'E')) {
        lexer->pos++;
        if (lexer->pos < lexer->end && (*lexer->pos == '+' || *lexer->pos == '-')) {
            lexer->pos++;
        }
        while (lexer->pos < lexer->end && *lexer->pos >= '0' && *lexer->pos <= '9') {
            lexer->pos++;
        }
    }
    
    token = cfscript_token_create(lexer, CFSCRIPT_NUMBER);
    if (token != NULL) {
        token->value.data = start;
        token->value.len = lexer->pos - start;
    }
    
    return token;
}

static cfscript_token_t *
cfscript_scan_identifier(cfscript_lexer_t *lexer)
{
    cfscript_token_t *token;
    u_char *start = lexer->pos;
    cfscript_token_type_t type;
    
    while (lexer->pos < lexer->end &&
           ((*lexer->pos >= 'a' && *lexer->pos <= 'z') ||
            (*lexer->pos >= 'A' && *lexer->pos <= 'Z') ||
            (*lexer->pos >= '0' && *lexer->pos <= '9') ||
            *lexer->pos == '_' || *lexer->pos == '$')) {
        lexer->pos++;
    }
    
    token = cfscript_token_create(lexer, CFSCRIPT_IDENTIFIER);
    if (token != NULL) {
        token->value.data = start;
        token->value.len = lexer->pos - start;
        
        /* Check for keyword */
        type = cfscript_lookup_keyword(&token->value);
        token->type = type;
    }
    
    return token;
}

cfscript_token_t *
cfscript_lexer_next(cfscript_lexer_t *lexer)
{
    cfscript_token_t *token;
    
    if (lexer->peek != NULL) {
        token = lexer->peek;
        lexer->peek = NULL;
        return token;
    }
    
    cfscript_skip_whitespace(lexer);
    
    while (lexer->pos + 1 < lexer->end &&
           ((*lexer->pos == '/' && *(lexer->pos + 1) == '/') ||
            (*lexer->pos == '/' && *(lexer->pos + 1) == '*'))) {
        cfscript_skip_comment(lexer);
        cfscript_skip_whitespace(lexer);
    }
    
    if (lexer->pos >= lexer->end) {
        return cfscript_token_create(lexer, CFSCRIPT_EOF);
    }
    
    /* String literals */
    if (*lexer->pos == '"' || *lexer->pos == '\'') {
        return cfscript_scan_string(lexer);
    }
    
    /* Numbers */
    if ((*lexer->pos >= '0' && *lexer->pos <= '9') ||
        (*lexer->pos == '.' && lexer->pos + 1 < lexer->end &&
         *(lexer->pos + 1) >= '0' && *(lexer->pos + 1) <= '9')) {
        return cfscript_scan_number(lexer);
    }
    
    /* Identifiers and keywords */
    if ((*lexer->pos >= 'a' && *lexer->pos <= 'z') ||
        (*lexer->pos >= 'A' && *lexer->pos <= 'Z') ||
        *lexer->pos == '_' || *lexer->pos == '$') {
        return cfscript_scan_identifier(lexer);
    }
    
    /* Operators and punctuation */
    token = cfscript_token_create(lexer, CFSCRIPT_ERROR);
    
    switch (*lexer->pos) {
    case '(':
        token->type = CFSCRIPT_LPAREN;
        lexer->pos++;
        break;
    case ')':
        token->type = CFSCRIPT_RPAREN;
        lexer->pos++;
        break;
    case '{':
        token->type = CFSCRIPT_LBRACE;
        lexer->pos++;
        break;
    case '}':
        token->type = CFSCRIPT_RBRACE;
        lexer->pos++;
        break;
    case '[':
        token->type = CFSCRIPT_LBRACKET;
        lexer->pos++;
        break;
    case ']':
        token->type = CFSCRIPT_RBRACKET;
        lexer->pos++;
        break;
    case ';':
        token->type = CFSCRIPT_SEMICOLON;
        lexer->pos++;
        break;
    case ',':
        token->type = CFSCRIPT_COMMA;
        lexer->pos++;
        break;
    case '.':
        if (lexer->pos + 2 < lexer->end &&
            *(lexer->pos + 1) == '.' && *(lexer->pos + 2) == '.') {
            token->type = CFSCRIPT_OP_SPREAD;
            lexer->pos += 3;
        } else {
            token->type = CFSCRIPT_DOT;
            lexer->pos++;
        }
        break;
    case '+':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '+') {
            token->type = CFSCRIPT_OP_INCREMENT;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_ADD;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_ADD;
            lexer->pos++;
        }
        break;
    case '-':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '-') {
            token->type = CFSCRIPT_OP_DECREMENT;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_SUB;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '>') {
            token->type = CFSCRIPT_OP_ARROW2;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_SUB;
            lexer->pos++;
        }
        break;
    case '*':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_MUL;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_MUL;
            lexer->pos++;
        }
        break;
    case '/':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_DIV;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_DIV;
            lexer->pos++;
        }
        break;
    case '%':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_MOD;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_MOD;
            lexer->pos++;
        }
        break;
    case '^':
        token->type = CFSCRIPT_OP_POWER;
        lexer->pos++;
        break;
    case '\\':
        token->type = CFSCRIPT_OP_INTDIV;
        lexer->pos++;
        break;
    case '&':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '&') {
            token->type = CFSCRIPT_OP_AND;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_ASSIGN_CONCAT;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_CONCAT;
            lexer->pos++;
        }
        break;
    case '|':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '|') {
            token->type = CFSCRIPT_OP_OR;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_ERROR;
            lexer->pos++;
        }
        break;
    case '!':
        if (lexer->pos + 2 < lexer->end &&
            *(lexer->pos + 1) == '=' && *(lexer->pos + 2) == '=') {
            token->type = CFSCRIPT_OP_STRICT_NEQ;
            lexer->pos += 3;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_NEQ;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_NOT;
            lexer->pos++;
        }
        break;
    case '=':
        if (lexer->pos + 2 < lexer->end &&
            *(lexer->pos + 1) == '=' && *(lexer->pos + 2) == '=') {
            token->type = CFSCRIPT_OP_STRICT_EQ;
            lexer->pos += 3;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_EQ;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '>') {
            token->type = CFSCRIPT_OP_ARROW;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_ASSIGN;
            lexer->pos++;
        }
        break;
    case '<':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_LTE;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_LT;
            lexer->pos++;
        }
        break;
    case '>':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '=') {
            token->type = CFSCRIPT_OP_GTE;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_GT;
            lexer->pos++;
        }
        break;
    case '?':
        if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == ':') {
            token->type = CFSCRIPT_OP_ELVIS;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '?') {
            token->type = CFSCRIPT_OP_NULL_COALESCE;
            lexer->pos += 2;
        } else if (lexer->pos + 1 < lexer->end && *(lexer->pos + 1) == '.') {
            token->type = CFSCRIPT_OP_SAFE_NAV;
            lexer->pos += 2;
        } else {
            token->type = CFSCRIPT_OP_TERNARY;
            lexer->pos++;
        }
        break;
    case ':':
        token->type = CFSCRIPT_OP_COLON;
        lexer->pos++;
        break;
    default:
        lexer->pos++;
        break;
    }
    
    return token;
}

cfscript_token_t *
cfscript_lexer_peek(cfscript_lexer_t *lexer)
{
    if (lexer->peek == NULL) {
        lexer->peek = cfscript_lexer_next(lexer);
    }
    return lexer->peek;
}

/* Parser implementation */
cfscript_parser_t *
cfscript_parser_create(ngx_pool_t *pool, u_char *input, size_t len)
{
    cfscript_parser_t *parser;
    
    parser = ngx_pcalloc(pool, sizeof(cfscript_parser_t));
    if (parser == NULL) {
        return NULL;
    }
    
    parser->pool = pool;
    parser->lexer = cfscript_lexer_create(pool, input, len);
    if (parser->lexer == NULL) {
        return NULL;
    }
    
    return parser;
}

static cfscript_ast_node_t *
cfscript_ast_create(cfscript_parser_t *parser, cfscript_ast_type_t type)
{
    cfscript_ast_node_t *node;
    
    node = ngx_pcalloc(parser->pool, sizeof(cfscript_ast_node_t));
    if (node == NULL) {
        return NULL;
    }
    
    node->type = type;
    node->pool = parser->pool;
    node->line = parser->lexer->line;
    node->column = parser->lexer->column;
    
    return node;
}

static ngx_int_t
cfscript_expect(cfscript_parser_t *parser, cfscript_token_type_t type)
{
    cfscript_token_t *token = cfscript_lexer_next(parser->lexer);
    return token->type == type ? NGX_OK : NGX_ERROR;
}

static cfscript_ast_node_t *cfscript_parse_block(cfscript_parser_t *parser);
static cfscript_ast_node_t *cfscript_parse_assignment(cfscript_parser_t *parser);

/* Parse primary expression */
static cfscript_ast_node_t *
cfscript_parse_primary(cfscript_parser_t *parser)
{
    cfscript_token_t *token = cfscript_lexer_next(parser->lexer);
    cfscript_ast_node_t *node;
    
    switch (token->type) {
    case CFSCRIPT_NUMBER:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_LITERAL_NUMBER);
        if (node != NULL) {
            node->data.number = ngx_atofp(token->value.data, token->value.len, 10);
        }
        return node;
        
    case CFSCRIPT_STRING:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_LITERAL_STRING);
        if (node != NULL) {
            node->data.string = token->value;
        }
        return node;
        
    case CFSCRIPT_KW_TRUE:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_LITERAL_BOOLEAN);
        if (node != NULL) {
            node->data.boolean = 1;
        }
        return node;
        
    case CFSCRIPT_KW_FALSE:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_LITERAL_BOOLEAN);
        if (node != NULL) {
            node->data.boolean = 0;
        }
        return node;
        
    case CFSCRIPT_KW_NULL:
        return cfscript_ast_create(parser, CFSCRIPT_AST_LITERAL_NULL);
        
    case CFSCRIPT_IDENTIFIER:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_IDENTIFIER);
        if (node != NULL) {
            node->data.identifier = token->value;
        }
        return node;
        
    case CFSCRIPT_LPAREN:
        node = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_RPAREN);
        return node;
        
    case CFSCRIPT_LBRACKET:
        /* Array literal */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_ARRAY_LITERAL);
        if (node != NULL) {
            node->data.statements = ngx_array_create(parser->pool, 8,
                                                      sizeof(cfscript_ast_node_t *));
            token = cfscript_lexer_peek(parser->lexer);
            while (token->type != CFSCRIPT_RBRACKET && token->type != CFSCRIPT_EOF) {
                cfscript_ast_node_t **elem = ngx_array_push(node->data.statements);
                *elem = cfscript_parse_expression(parser);
                token = cfscript_lexer_peek(parser->lexer);
                if (token->type == CFSCRIPT_COMMA) {
                    cfscript_lexer_next(parser->lexer);
                    token = cfscript_lexer_peek(parser->lexer);
                }
            }
            cfscript_expect(parser, CFSCRIPT_RBRACKET);
        }
        return node;
        
    case CFSCRIPT_LBRACE:
        /* Struct literal */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_STRUCT_LITERAL);
        if (node != NULL) {
            node->data.statements = ngx_array_create(parser->pool, 8,
                                                      sizeof(cfscript_ast_node_t *));
            token = cfscript_lexer_peek(parser->lexer);
            while (token->type != CFSCRIPT_RBRACE && token->type != CFSCRIPT_EOF) {
                /* key: value or key = value */
                cfscript_ast_node_t *pair = cfscript_ast_create(parser, CFSCRIPT_AST_ASSIGNMENT);
                pair->data.binary.left = cfscript_parse_primary(parser);
                token = cfscript_lexer_next(parser->lexer);
                if (token->type == CFSCRIPT_OP_COLON || token->type == CFSCRIPT_OP_ASSIGN) {
                    pair->data.binary.right = cfscript_parse_expression(parser);
                }
                cfscript_ast_node_t **elem = ngx_array_push(node->data.statements);
                *elem = pair;
                
                token = cfscript_lexer_peek(parser->lexer);
                if (token->type == CFSCRIPT_COMMA) {
                    cfscript_lexer_next(parser->lexer);
                    token = cfscript_lexer_peek(parser->lexer);
                }
            }
            cfscript_expect(parser, CFSCRIPT_RBRACE);
        }
        return node;
        
    case CFSCRIPT_KW_NEW:
        /* new Component() */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_NEW);
        if (node != NULL) {
            token = cfscript_lexer_next(parser->lexer);
            node->data.new_expr.component = token->value;
            node->data.new_expr.arguments = ngx_array_create(parser->pool, 4,
                                                              sizeof(cfscript_ast_node_t *));
            if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_LPAREN) {
                cfscript_lexer_next(parser->lexer);
                token = cfscript_lexer_peek(parser->lexer);
                while (token->type != CFSCRIPT_RPAREN && token->type != CFSCRIPT_EOF) {
                    cfscript_ast_node_t **arg = ngx_array_push(node->data.new_expr.arguments);
                    *arg = cfscript_parse_expression(parser);
                    token = cfscript_lexer_peek(parser->lexer);
                    if (token->type == CFSCRIPT_COMMA) {
                        cfscript_lexer_next(parser->lexer);
                        token = cfscript_lexer_peek(parser->lexer);
                    }
                }
                cfscript_expect(parser, CFSCRIPT_RPAREN);
            }
        }
        return node;
        
    case CFSCRIPT_KW_FUNCTION:
        /* Anonymous function / closure */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_CLOSURE);
        if (node != NULL) {
            node->data.closure.params = ngx_array_create(parser->pool, 4,
                                                          sizeof(cfscript_ast_node_t *));
            cfscript_expect(parser, CFSCRIPT_LPAREN);
            token = cfscript_lexer_peek(parser->lexer);
            while (token->type != CFSCRIPT_RPAREN && token->type != CFSCRIPT_EOF) {
                cfscript_ast_node_t *param = cfscript_ast_create(parser, CFSCRIPT_AST_PARAM);
                token = cfscript_lexer_next(parser->lexer);
                param->data.param.name = token->value;
                cfscript_ast_node_t **p = ngx_array_push(node->data.closure.params);
                *p = param;
                
                token = cfscript_lexer_peek(parser->lexer);
                if (token->type == CFSCRIPT_COMMA) {
                    cfscript_lexer_next(parser->lexer);
                    token = cfscript_lexer_peek(parser->lexer);
                }
            }
            cfscript_expect(parser, CFSCRIPT_RPAREN);
            node->data.closure.body = cfscript_parse_block(parser);
        }
        return node;
        
    default:
        return NULL;
    }
}

/* Parse postfix expressions */
static cfscript_ast_node_t *
cfscript_parse_postfix(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *node = cfscript_parse_primary(parser);
    cfscript_token_t *token;
    
    while (node != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_DOT || token->type == CFSCRIPT_OP_SAFE_NAV) {
            /* Member access */
            cfscript_ast_node_t *member = cfscript_ast_create(parser, CFSCRIPT_AST_MEMBER);
            cfscript_lexer_next(parser->lexer);
            member->data.member.object = node;
            member->data.member.safe_navigation = (token->type == CFSCRIPT_OP_SAFE_NAV);
            token = cfscript_lexer_next(parser->lexer);
            member->data.member.property = token->value;
            node = member;
            
        } else if (token->type == CFSCRIPT_LBRACKET) {
            /* Index access */
            cfscript_ast_node_t *index = cfscript_ast_create(parser, CFSCRIPT_AST_INDEX);
            cfscript_lexer_next(parser->lexer);
            index->data.index.object = node;
            index->data.index.index = cfscript_parse_expression(parser);
            cfscript_expect(parser, CFSCRIPT_RBRACKET);
            node = index;
            
        } else if (token->type == CFSCRIPT_LPAREN) {
            /* Function call */
            cfscript_ast_node_t *call = cfscript_ast_create(parser, CFSCRIPT_AST_CALL);
            cfscript_lexer_next(parser->lexer);
            call->data.call.callee = node;
            call->data.call.arguments = ngx_array_create(parser->pool, 4,
                                                          sizeof(cfscript_ast_node_t *));
            token = cfscript_lexer_peek(parser->lexer);
            while (token->type != CFSCRIPT_RPAREN && token->type != CFSCRIPT_EOF) {
                cfscript_ast_node_t **arg = ngx_array_push(call->data.call.arguments);
                *arg = cfscript_parse_expression(parser);
                token = cfscript_lexer_peek(parser->lexer);
                if (token->type == CFSCRIPT_COMMA) {
                    cfscript_lexer_next(parser->lexer);
                    token = cfscript_lexer_peek(parser->lexer);
                }
            }
            cfscript_expect(parser, CFSCRIPT_RPAREN);
            node = call;
            
        } else if (token->type == CFSCRIPT_OP_INCREMENT || token->type == CFSCRIPT_OP_DECREMENT) {
            /* Postfix increment/decrement */
            cfscript_ast_node_t *unary = cfscript_ast_create(parser, CFSCRIPT_AST_POSTFIX);
            cfscript_lexer_next(parser->lexer);
            unary->data.unary.op = token->type;
            unary->data.unary.operand = node;
            unary->data.unary.is_prefix = 0;
            node = unary;
            
        } else {
            break;
        }
    }
    
    return node;
}

/* Parse unary expressions */
static cfscript_ast_node_t *
cfscript_parse_unary(cfscript_parser_t *parser)
{
    cfscript_token_t *token = cfscript_lexer_peek(parser->lexer);
    
    if (token->type == CFSCRIPT_OP_NOT ||
        token->type == CFSCRIPT_OP_SUB ||
        token->type == CFSCRIPT_OP_INCREMENT ||
        token->type == CFSCRIPT_OP_DECREMENT) {
        cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_PREFIX);
        cfscript_lexer_next(parser->lexer);
        node->data.unary.op = token->type;
        node->data.unary.operand = cfscript_parse_unary(parser);
        node->data.unary.is_prefix = 1;
        return node;
    }
    
    return cfscript_parse_postfix(parser);
}

/* Parse multiplicative expressions */
static cfscript_ast_node_t *
cfscript_parse_multiplicative(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_unary(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_MUL ||
            token->type == CFSCRIPT_OP_DIV ||
            token->type == CFSCRIPT_OP_MOD ||
            token->type == CFSCRIPT_OP_INTDIV ||
            token->type == CFSCRIPT_OP_POWER) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_unary(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse additive expressions */
static cfscript_ast_node_t *
cfscript_parse_additive(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_multiplicative(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_ADD ||
            token->type == CFSCRIPT_OP_SUB ||
            token->type == CFSCRIPT_OP_CONCAT) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_multiplicative(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse comparison expressions */
static cfscript_ast_node_t *
cfscript_parse_comparison(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_additive(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_LT ||
            token->type == CFSCRIPT_OP_GT ||
            token->type == CFSCRIPT_OP_LTE ||
            token->type == CFSCRIPT_OP_GTE) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_additive(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse equality expressions */
static cfscript_ast_node_t *
cfscript_parse_equality(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_comparison(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_EQ ||
            token->type == CFSCRIPT_OP_NEQ ||
            token->type == CFSCRIPT_OP_STRICT_EQ ||
            token->type == CFSCRIPT_OP_STRICT_NEQ) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_comparison(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse logical AND */
static cfscript_ast_node_t *
cfscript_parse_logical_and(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_equality(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_AND) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_equality(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse logical OR */
static cfscript_ast_node_t *
cfscript_parse_logical_or(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_logical_and(parser);
    cfscript_token_t *token;
    
    while (left != NULL) {
        token = cfscript_lexer_peek(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_OR) {
            cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
            cfscript_lexer_next(parser->lexer);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_logical_and(parser);
            left = node;
        } else {
            break;
        }
    }
    
    return left;
}

/* Parse ternary */
static cfscript_ast_node_t *
cfscript_parse_ternary(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *condition = cfscript_parse_logical_or(parser);
    cfscript_token_t *token = cfscript_lexer_peek(parser->lexer);
    
    if (token->type == CFSCRIPT_OP_TERNARY) {
        cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_TERNARY);
        cfscript_lexer_next(parser->lexer);
        node->data.ternary.condition = condition;
        node->data.ternary.then_expr = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_OP_COLON);
        node->data.ternary.else_expr = cfscript_parse_ternary(parser);
        return node;
    }
    
    if (token->type == CFSCRIPT_OP_ELVIS || token->type == CFSCRIPT_OP_NULL_COALESCE) {
        cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BINARY);
        cfscript_lexer_next(parser->lexer);
        node->data.binary.op = token->type;
        node->data.binary.left = condition;
        node->data.binary.right = cfscript_parse_ternary(parser);
        return node;
    }
    
    return condition;
}

/* Parse assignment */
static cfscript_ast_node_t *
cfscript_parse_assignment(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *left = cfscript_parse_ternary(parser);
    cfscript_token_t *token = cfscript_lexer_peek(parser->lexer);
    
    if (token->type == CFSCRIPT_OP_ASSIGN ||
        token->type == CFSCRIPT_OP_ASSIGN_ADD ||
        token->type == CFSCRIPT_OP_ASSIGN_SUB ||
        token->type == CFSCRIPT_OP_ASSIGN_MUL ||
        token->type == CFSCRIPT_OP_ASSIGN_DIV ||
        token->type == CFSCRIPT_OP_ASSIGN_MOD ||
        token->type == CFSCRIPT_OP_ASSIGN_CONCAT) {
        cfscript_ast_node_t *node;
        cfscript_lexer_next(parser->lexer);
        
        if (token->type == CFSCRIPT_OP_ASSIGN) {
            node = cfscript_ast_create(parser, CFSCRIPT_AST_ASSIGNMENT);
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_assignment(parser);
        } else {
            node = cfscript_ast_create(parser, CFSCRIPT_AST_COMPOUND_ASSIGN);
            node->data.binary.op = token->type;
            node->data.binary.left = left;
            node->data.binary.right = cfscript_parse_assignment(parser);
        }
        return node;
    }
    
    return left;
}

cfscript_ast_node_t *
cfscript_parse_expression(cfscript_parser_t *parser)
{
    return cfscript_parse_assignment(parser);
}

/* Parse block */
static cfscript_ast_node_t *
cfscript_parse_block(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_BLOCK);
    cfscript_token_t *token;
    
    node->data.statements = ngx_array_create(parser->pool, 16,
                                              sizeof(cfscript_ast_node_t *));
    
    cfscript_expect(parser, CFSCRIPT_LBRACE);
    
    token = cfscript_lexer_peek(parser->lexer);
    while (token->type != CFSCRIPT_RBRACE && token->type != CFSCRIPT_EOF) {
        cfscript_ast_node_t *stmt = cfscript_parse_statement(parser);
        if (stmt != NULL) {
            cfscript_ast_node_t **s = ngx_array_push(node->data.statements);
            *s = stmt;
        }
        token = cfscript_lexer_peek(parser->lexer);
    }
    
    cfscript_expect(parser, CFSCRIPT_RBRACE);
    
    return node;
}

/* Parse statement */
cfscript_ast_node_t *
cfscript_parse_statement(cfscript_parser_t *parser)
{
    cfscript_token_t *token = cfscript_lexer_peek(parser->lexer);
    cfscript_ast_node_t *node;
    
    switch (token->type) {
    case CFSCRIPT_KW_VAR:
    case CFSCRIPT_KW_LOCAL:
        /* Variable declaration */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_VAR_DECL);
        node->data.var_decl.is_local = (token->type == CFSCRIPT_KW_LOCAL);
        cfscript_lexer_next(parser->lexer);
        token = cfscript_lexer_next(parser->lexer);
        node->data.var_decl.name = token->value;
        token = cfscript_lexer_peek(parser->lexer);
        if (token->type == CFSCRIPT_OP_ASSIGN) {
            cfscript_lexer_next(parser->lexer);
            node->data.var_decl.init = cfscript_parse_expression(parser);
        }
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_KW_IF:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_IF);
        cfscript_lexer_next(parser->lexer);
        cfscript_expect(parser, CFSCRIPT_LPAREN);
        node->data.if_stmt.condition = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_RPAREN);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_LBRACE) {
            node->data.if_stmt.then_branch = cfscript_parse_block(parser);
        } else {
            node->data.if_stmt.then_branch = cfscript_parse_statement(parser);
        }
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_KW_ELSE) {
            cfscript_lexer_next(parser->lexer);
            if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_LBRACE) {
                node->data.if_stmt.else_branch = cfscript_parse_block(parser);
            } else {
                node->data.if_stmt.else_branch = cfscript_parse_statement(parser);
            }
        }
        return node;
        
    case CFSCRIPT_KW_FOR:
        cfscript_lexer_next(parser->lexer);
        cfscript_expect(parser, CFSCRIPT_LPAREN);
        token = cfscript_lexer_peek(parser->lexer);
        
        /* Check for for-in loop */
        if (token->type == CFSCRIPT_KW_VAR || token->type == CFSCRIPT_IDENTIFIER) {
            cfscript_token_t *lookahead = cfscript_lexer_next(parser->lexer);
            ngx_str_t var_name = lookahead->value;
            token = cfscript_lexer_peek(parser->lexer);
            
            if (token->type == CFSCRIPT_KW_IN) {
                node = cfscript_ast_create(parser, CFSCRIPT_AST_FOR_IN);
                cfscript_lexer_next(parser->lexer);
                node->data.for_in.variable = var_name;
                node->data.for_in.collection = cfscript_parse_expression(parser);
                cfscript_expect(parser, CFSCRIPT_RPAREN);
                node->data.for_in.body = cfscript_parse_block(parser);
                return node;
            }
            
            /* Regular for loop */
            node = cfscript_ast_create(parser, CFSCRIPT_AST_FOR);
            /* Parse init as var decl or assignment */
            cfscript_ast_node_t *init = cfscript_ast_create(parser, CFSCRIPT_AST_ASSIGNMENT);
            init->data.binary.left = cfscript_ast_create(parser, CFSCRIPT_AST_IDENTIFIER);
            init->data.binary.left->data.identifier = var_name;
            if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_OP_ASSIGN) {
                cfscript_lexer_next(parser->lexer);
                init->data.binary.right = cfscript_parse_expression(parser);
            }
            node->data.for_loop.init = init;
        } else {
            node = cfscript_ast_create(parser, CFSCRIPT_AST_FOR);
            node->data.for_loop.init = cfscript_parse_expression(parser);
        }
        
        cfscript_expect(parser, CFSCRIPT_SEMICOLON);
        node->data.for_loop.condition = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_SEMICOLON);
        node->data.for_loop.update = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_RPAREN);
        node->data.for_loop.body = cfscript_parse_block(parser);
        return node;
        
    case CFSCRIPT_KW_WHILE:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_WHILE);
        cfscript_lexer_next(parser->lexer);
        cfscript_expect(parser, CFSCRIPT_LPAREN);
        node->data.while_loop.condition = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_RPAREN);
        node->data.while_loop.body = cfscript_parse_block(parser);
        return node;
        
    case CFSCRIPT_KW_DO:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_DO_WHILE);
        cfscript_lexer_next(parser->lexer);
        node->data.while_loop.body = cfscript_parse_block(parser);
        cfscript_expect(parser, CFSCRIPT_KW_WHILE);
        cfscript_expect(parser, CFSCRIPT_LPAREN);
        node->data.while_loop.condition = cfscript_parse_expression(parser);
        cfscript_expect(parser, CFSCRIPT_RPAREN);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_KW_RETURN:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_RETURN);
        cfscript_lexer_next(parser->lexer);
        token = cfscript_lexer_peek(parser->lexer);
        if (token->type != CFSCRIPT_SEMICOLON && token->type != CFSCRIPT_RBRACE) {
            node->data.return_value = cfscript_parse_expression(parser);
        }
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_KW_BREAK:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_BREAK);
        cfscript_lexer_next(parser->lexer);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_KW_CONTINUE:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_CONTINUE);
        cfscript_lexer_next(parser->lexer);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_KW_TRY:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_TRY);
        cfscript_lexer_next(parser->lexer);
        node->data.try_stmt.try_block = cfscript_parse_block(parser);
        node->data.try_stmt.catch_blocks = ngx_array_create(parser->pool, 2,
                                                             sizeof(cfscript_ast_node_t *));
        while (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_KW_CATCH) {
            cfscript_ast_node_t *catch_node = cfscript_ast_create(parser, CFSCRIPT_AST_CATCH);
            cfscript_lexer_next(parser->lexer);
            cfscript_expect(parser, CFSCRIPT_LPAREN);
            token = cfscript_lexer_next(parser->lexer);
            catch_node->data.catch_stmt.variable = token->value;
            cfscript_expect(parser, CFSCRIPT_RPAREN);
            catch_node->data.catch_stmt.body = cfscript_parse_block(parser);
            cfscript_ast_node_t **c = ngx_array_push(node->data.try_stmt.catch_blocks);
            *c = catch_node;
        }
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_KW_FINALLY) {
            cfscript_lexer_next(parser->lexer);
            node->data.try_stmt.finally_block = cfscript_parse_block(parser);
        }
        return node;
        
    case CFSCRIPT_KW_THROW:
        node = cfscript_ast_create(parser, CFSCRIPT_AST_THROW);
        cfscript_lexer_next(parser->lexer);
        node->data.throw_stmt.expression = cfscript_parse_expression(parser);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
        
    case CFSCRIPT_LBRACE:
        return cfscript_parse_block(parser);
        
    case CFSCRIPT_SEMICOLON:
        cfscript_lexer_next(parser->lexer);
        return NULL;
        
    default:
        /* Expression statement */
        node = cfscript_ast_create(parser, CFSCRIPT_AST_EXPRESSION_STMT);
        node->data.return_value = cfscript_parse_expression(parser);
        if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
            cfscript_lexer_next(parser->lexer);
        }
        return node;
    }
}

/* Parse function definition */
cfscript_ast_node_t *
cfscript_parse_function(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_FUNCTION);
    cfscript_token_t *token;
    
    /* Parse access and modifiers */
    token = cfscript_lexer_peek(parser->lexer);
    while (token->type == CFSCRIPT_KW_PUBLIC ||
           token->type == CFSCRIPT_KW_PRIVATE ||
           token->type == CFSCRIPT_KW_REMOTE ||
           token->type == CFSCRIPT_KW_PACKAGE ||
           token->type == CFSCRIPT_KW_STATIC ||
           token->type == CFSCRIPT_KW_FINAL ||
           token->type == CFSCRIPT_KW_ABSTRACT) {
        if (token->type == CFSCRIPT_KW_PUBLIC) {
            ngx_str_set(&node->data.function.access, "public");
        } else if (token->type == CFSCRIPT_KW_PRIVATE) {
            ngx_str_set(&node->data.function.access, "private");
        } else if (token->type == CFSCRIPT_KW_REMOTE) {
            ngx_str_set(&node->data.function.access, "remote");
        } else if (token->type == CFSCRIPT_KW_STATIC) {
            node->data.function.is_static = 1;
        } else if (token->type == CFSCRIPT_KW_FINAL) {
            node->data.function.is_final = 1;
        } else if (token->type == CFSCRIPT_KW_ABSTRACT) {
            node->data.function.is_abstract = 1;
        }
        cfscript_lexer_next(parser->lexer);
        token = cfscript_lexer_peek(parser->lexer);
    }
    
    /* Parse return type if present */
    if (token->type >= CFSCRIPT_TYPE_ANY && token->type <= CFSCRIPT_TYPE_XML) {
        cfscript_lexer_next(parser->lexer);
        node->data.function.return_type = token->value;
        token = cfscript_lexer_peek(parser->lexer);
    }
    
    /* Parse function keyword */
    if (token->type == CFSCRIPT_KW_FUNCTION) {
        cfscript_lexer_next(parser->lexer);
    }
    
    /* Parse name */
    token = cfscript_lexer_next(parser->lexer);
    node->data.function.name = token->value;
    
    /* Parse parameters */
    node->data.function.params = ngx_array_create(parser->pool, 4,
                                                   sizeof(cfscript_ast_node_t *));
    cfscript_expect(parser, CFSCRIPT_LPAREN);
    token = cfscript_lexer_peek(parser->lexer);
    while (token->type != CFSCRIPT_RPAREN && token->type != CFSCRIPT_EOF) {
        cfscript_ast_node_t *param = cfscript_ast_create(parser, CFSCRIPT_AST_PARAM);
        
        /* required keyword */
        if (token->type == CFSCRIPT_KW_REQUIRED) {
            param->data.param.required = 1;
            cfscript_lexer_next(parser->lexer);
            token = cfscript_lexer_peek(parser->lexer);
        }
        
        /* type */
        if (token->type >= CFSCRIPT_TYPE_ANY && token->type <= CFSCRIPT_TYPE_XML) {
            cfscript_lexer_next(parser->lexer);
            param->data.param.type = token->value;
            token = cfscript_lexer_peek(parser->lexer);
        }
        
        /* name */
        token = cfscript_lexer_next(parser->lexer);
        param->data.param.name = token->value;
        
        /* default value */
        token = cfscript_lexer_peek(parser->lexer);
        if (token->type == CFSCRIPT_OP_ASSIGN) {
            cfscript_lexer_next(parser->lexer);
            param->data.param.default_value = cfscript_parse_expression(parser);
        }
        
        cfscript_ast_node_t **p = ngx_array_push(node->data.function.params);
        *p = param;
        
        token = cfscript_lexer_peek(parser->lexer);
        if (token->type == CFSCRIPT_COMMA) {
            cfscript_lexer_next(parser->lexer);
            token = cfscript_lexer_peek(parser->lexer);
        }
    }
    cfscript_expect(parser, CFSCRIPT_RPAREN);
    
    /* Parse body */
    if (!node->data.function.is_abstract) {
        node->data.function.body = cfscript_parse_block(parser);
    }
    
    return node;
}

/* Parse component */
cfscript_ast_node_t *
cfscript_parse_component(cfscript_parser_t *parser)
{
    cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_COMPONENT);
    cfscript_token_t *token;
    
    cfscript_expect(parser, CFSCRIPT_KW_COMPONENT);
    
    node->data.component.properties = ngx_array_create(parser->pool, 8,
                                                        sizeof(cfscript_ast_node_t *));
    node->data.component.functions = ngx_array_create(parser->pool, 16,
                                                       sizeof(cfscript_ast_node_t *));
    
    /* Parse component body */
    cfscript_expect(parser, CFSCRIPT_LBRACE);
    
    token = cfscript_lexer_peek(parser->lexer);
    while (token->type != CFSCRIPT_RBRACE && token->type != CFSCRIPT_EOF) {
        if (token->type == CFSCRIPT_KW_PROPERTY) {
            /* Parse property */
            cfscript_ast_node_t *prop = cfscript_ast_create(parser, CFSCRIPT_AST_PROPERTY);
            cfscript_lexer_next(parser->lexer);
            token = cfscript_lexer_next(parser->lexer);
            prop->data.property.name = token->value;
            if (cfscript_lexer_peek(parser->lexer)->type == CFSCRIPT_SEMICOLON) {
                cfscript_lexer_next(parser->lexer);
            }
            cfscript_ast_node_t **p = ngx_array_push(node->data.component.properties);
            *p = prop;
        } else if (token->type == CFSCRIPT_KW_FUNCTION ||
                   token->type == CFSCRIPT_KW_PUBLIC ||
                   token->type == CFSCRIPT_KW_PRIVATE ||
                   token->type == CFSCRIPT_KW_REMOTE ||
                   token->type == CFSCRIPT_KW_STATIC ||
                   (token->type >= CFSCRIPT_TYPE_ANY && token->type <= CFSCRIPT_TYPE_XML)) {
            cfscript_ast_node_t *func = cfscript_parse_function(parser);
            cfscript_ast_node_t **f = ngx_array_push(node->data.component.functions);
            *f = func;
        } else {
            /* Skip unknown tokens */
            cfscript_lexer_next(parser->lexer);
        }
        
        token = cfscript_lexer_peek(parser->lexer);
    }
    
    cfscript_expect(parser, CFSCRIPT_RBRACE);
    
    return node;
}

/* Parse program */
cfscript_ast_node_t *
cfscript_parse(cfscript_parser_t *parser)
{
    cfscript_token_t *token = cfscript_lexer_peek(parser->lexer);
    
    if (token->type == CFSCRIPT_KW_COMPONENT) {
        return cfscript_parse_component(parser);
    }
    
    if (token->type == CFSCRIPT_KW_INTERFACE) {
        /* Similar to component */
        return cfscript_parse_component(parser);
    }
    
    /* Parse as script block */
    cfscript_ast_node_t *node = cfscript_ast_create(parser, CFSCRIPT_AST_PROGRAM);
    node->data.statements = ngx_array_create(parser->pool, 32,
                                              sizeof(cfscript_ast_node_t *));
    
    while (cfscript_lexer_peek(parser->lexer)->type != CFSCRIPT_EOF) {
        cfscript_ast_node_t *stmt = cfscript_parse_statement(parser);
        if (stmt != NULL) {
            cfscript_ast_node_t **s = ngx_array_push(node->data.statements);
            *s = stmt;
        }
    }
    
    return node;
}

/* Execute CFScript AST - forwards to runtime */
ngx_int_t
cfscript_execute(cfml_context_t *ctx, cfscript_ast_node_t *node)
{
    /* Convert to CFML AST and execute */
    cfml_ast_node_t *cfml_node = cfscript_to_cfml_ast(ctx->pool, node);
    if (cfml_node == NULL) {
        return NGX_ERROR;
    }
    return cfml_execute(ctx, cfml_node);
}

/* Convert CFScript AST to CFML AST for unified execution */
cfml_ast_node_t *
cfscript_to_cfml_ast(ngx_pool_t *pool, cfscript_ast_node_t *node)
{
    /* Simplified conversion - full implementation would handle all node types */
    cfml_ast_node_t *cfml;
    
    if (node == NULL) {
        return NULL;
    }
    
    cfml = ngx_pcalloc(pool, sizeof(cfml_ast_node_t));
    if (cfml == NULL) {
        return NULL;
    }
    
    cfml->pool = pool;
    cfml->line = node->line;
    cfml->column = node->column;
    
    /* Map types - simplified */
    switch (node->type) {
    case CFSCRIPT_AST_LITERAL_NUMBER:
        cfml->type = CFML_AST_EXPR_LITERAL;
        cfml->data.literal = cfml_create_float(pool, node->data.number);
        break;
        
    case CFSCRIPT_AST_LITERAL_STRING:
        cfml->type = CFML_AST_EXPR_LITERAL;
        cfml->data.literal = cfml_create_string(pool, &node->data.string);
        break;
        
    case CFSCRIPT_AST_LITERAL_BOOLEAN:
        cfml->type = CFML_AST_EXPR_LITERAL;
        cfml->data.literal = cfml_create_boolean(pool, node->data.boolean);
        break;
        
    case CFSCRIPT_AST_LITERAL_NULL:
        cfml->type = CFML_AST_EXPR_LITERAL;
        cfml->data.literal = cfml_create_null(pool);
        break;
        
    case CFSCRIPT_AST_IDENTIFIER:
        cfml->type = CFML_AST_EXPR_VARIABLE;
        cfml->data.variable.name = node->data.identifier;
        break;
        
    default:
        cfml->type = CFML_AST_TEXT;
        break;
    }
    
    return cfml;
}
