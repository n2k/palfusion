/*
 * CFML JSON - Native JSON support
 * Full JSON parser and serializer without external dependencies
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>
#include "cfml_json.h"
#include "cfml_variables.h"

#define JSON_MAX_DEPTH 512
#define JSON_INITIAL_BUF_SIZE 4096

/* Forward declarations */
static cfml_value_t *json_parse_value(cfml_json_parser_t *parser);
static ngx_int_t json_next_token(cfml_json_parser_t *parser);
static void json_skip_whitespace(cfml_json_parser_t *parser);
static ngx_int_t json_serialize_value(cfml_json_writer_t *writer, 
                                       cfml_value_t *value, ngx_uint_t depth);

/*
 * JSON Parser Implementation
 */

static void
json_skip_whitespace(cfml_json_parser_t *parser)
{
    while (parser->pos < parser->end) {
        switch (*parser->pos) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            parser->pos++;
            break;
        default:
            return;
        }
    }
}

static ngx_int_t
json_parse_string(cfml_json_parser_t *parser)
{
    u_char *start, *dst;
    u_char c;
    
    if (*parser->pos != '"') {
        return NGX_ERROR;
    }
    
    parser->pos++;  /* Skip opening quote */
    start = parser->pos;
    dst = start;
    
    while (parser->pos < parser->end) {
        c = *parser->pos;
        
        if (c == '"') {
            parser->current.type = JSON_TOKEN_STRING;
            parser->current.value.data = start;
            parser->current.value.len = dst - start;
            parser->pos++;  /* Skip closing quote */
            return NGX_OK;
        }
        
        if (c == '\\') {
            parser->pos++;
            if (parser->pos >= parser->end) {
                parser->error.data = (u_char *)"Unexpected end in string escape";
                parser->error.len = 30;
                return NGX_ERROR;
            }
            
            c = *parser->pos;
            switch (c) {
            case '"':  *dst++ = '"';  break;
            case '\\': *dst++ = '\\'; break;
            case '/':  *dst++ = '/';  break;
            case 'b':  *dst++ = '\b'; break;
            case 'f':  *dst++ = '\f'; break;
            case 'n':  *dst++ = '\n'; break;
            case 'r':  *dst++ = '\r'; break;
            case 't':  *dst++ = '\t'; break;
            case 'u':
                /* Unicode escape \uXXXX */
                if (parser->pos + 4 >= parser->end) {
                    parser->error.data = (u_char *)"Invalid unicode escape";
                    parser->error.len = 22;
                    return NGX_ERROR;
                }
                {
                    uint32_t codepoint = 0;
                    ngx_uint_t i;
                    for (i = 1; i <= 4; i++) {
                        c = parser->pos[i];
                        codepoint <<= 4;
                        if (c >= '0' && c <= '9') {
                            codepoint |= c - '0';
                        } else if (c >= 'a' && c <= 'f') {
                            codepoint |= c - 'a' + 10;
                        } else if (c >= 'A' && c <= 'F') {
                            codepoint |= c - 'A' + 10;
                        } else {
                            parser->error.data = (u_char *)"Invalid unicode escape";
                            parser->error.len = 22;
                            return NGX_ERROR;
                        }
                    }
                    parser->pos += 4;
                    
                    /* Encode as UTF-8 */
                    if (codepoint < 0x80) {
                        *dst++ = (u_char)codepoint;
                    } else if (codepoint < 0x800) {
                        *dst++ = 0xC0 | (codepoint >> 6);
                        *dst++ = 0x80 | (codepoint & 0x3F);
                    } else if (codepoint < 0x10000) {
                        *dst++ = 0xE0 | (codepoint >> 12);
                        *dst++ = 0x80 | ((codepoint >> 6) & 0x3F);
                        *dst++ = 0x80 | (codepoint & 0x3F);
                    } else {
                        *dst++ = 0xF0 | (codepoint >> 18);
                        *dst++ = 0x80 | ((codepoint >> 12) & 0x3F);
                        *dst++ = 0x80 | ((codepoint >> 6) & 0x3F);
                        *dst++ = 0x80 | (codepoint & 0x3F);
                    }
                }
                break;
            default:
                parser->error.data = (u_char *)"Invalid escape sequence";
                parser->error.len = 23;
                return NGX_ERROR;
            }
            parser->pos++;
        } else if ((u_char)c < 0x20) {
            parser->error.data = (u_char *)"Control character in string";
            parser->error.len = 27;
            return NGX_ERROR;
        } else {
            *dst++ = c;
            parser->pos++;
        }
    }
    
    parser->error.data = (u_char *)"Unterminated string";
    parser->error.len = 19;
    return NGX_ERROR;
}

static ngx_int_t
json_parse_number(cfml_json_parser_t *parser)
{
    u_char *start = parser->pos;
    double value = 0;
    double fraction = 0;
    double divisor = 1;
    int exponent = 0;
    int exp_sign = 1;
    int negative = 0;
    
    /* Sign */
    if (*parser->pos == '-') {
        negative = 1;
        parser->pos++;
    }
    
    /* Integer part */
    if (parser->pos >= parser->end) {
        parser->error.data = (u_char *)"Invalid number";
        parser->error.len = 14;
        return NGX_ERROR;
    }
    
    if (*parser->pos == '0') {
        parser->pos++;
    } else if (*parser->pos >= '1' && *parser->pos <= '9') {
        while (parser->pos < parser->end && *parser->pos >= '0' && *parser->pos <= '9') {
            value = value * 10 + (*parser->pos - '0');
            parser->pos++;
        }
    } else {
        parser->error.data = (u_char *)"Invalid number";
        parser->error.len = 14;
        return NGX_ERROR;
    }
    
    /* Fraction */
    if (parser->pos < parser->end && *parser->pos == '.') {
        parser->pos++;
        if (parser->pos >= parser->end || *parser->pos < '0' || *parser->pos > '9') {
            parser->error.data = (u_char *)"Invalid number fraction";
            parser->error.len = 23;
            return NGX_ERROR;
        }
        while (parser->pos < parser->end && *parser->pos >= '0' && *parser->pos <= '9') {
            divisor *= 10;
            fraction = fraction * 10 + (*parser->pos - '0');
            parser->pos++;
        }
        value += fraction / divisor;
    }
    
    /* Exponent */
    if (parser->pos < parser->end && (*parser->pos == 'e' || *parser->pos == 'E')) {
        parser->pos++;
        if (parser->pos < parser->end) {
            if (*parser->pos == '+') {
                parser->pos++;
            } else if (*parser->pos == '-') {
                exp_sign = -1;
                parser->pos++;
            }
        }
        if (parser->pos >= parser->end || *parser->pos < '0' || *parser->pos > '9') {
            parser->error.data = (u_char *)"Invalid number exponent";
            parser->error.len = 23;
            return NGX_ERROR;
        }
        while (parser->pos < parser->end && *parser->pos >= '0' && *parser->pos <= '9') {
            exponent = exponent * 10 + (*parser->pos - '0');
            parser->pos++;
        }
        value *= pow(10.0, exp_sign * exponent);
    }
    
    if (negative) {
        value = -value;
    }
    
    parser->current.type = JSON_TOKEN_NUMBER;
    parser->current.value.data = start;
    parser->current.value.len = parser->pos - start;
    parser->current.number = value;
    
    return NGX_OK;
}

static ngx_int_t
json_next_token(cfml_json_parser_t *parser)
{
    json_skip_whitespace(parser);
    
    if (parser->pos >= parser->end) {
        parser->current.type = JSON_TOKEN_EOF;
        return NGX_OK;
    }
    
    switch (*parser->pos) {
    case '{':
        parser->current.type = JSON_TOKEN_LBRACE;
        parser->pos++;
        return NGX_OK;
        
    case '}':
        parser->current.type = JSON_TOKEN_RBRACE;
        parser->pos++;
        return NGX_OK;
        
    case '[':
        parser->current.type = JSON_TOKEN_LBRACKET;
        parser->pos++;
        return NGX_OK;
        
    case ']':
        parser->current.type = JSON_TOKEN_RBRACKET;
        parser->pos++;
        return NGX_OK;
        
    case ':':
        parser->current.type = JSON_TOKEN_COLON;
        parser->pos++;
        return NGX_OK;
        
    case ',':
        parser->current.type = JSON_TOKEN_COMMA;
        parser->pos++;
        return NGX_OK;
        
    case '"':
        return json_parse_string(parser);
        
    case 't':
        if (parser->pos + 4 <= parser->end && 
            ngx_strncmp(parser->pos, "true", 4) == 0) {
            parser->current.type = JSON_TOKEN_TRUE;
            parser->pos += 4;
            return NGX_OK;
        }
        break;
        
    case 'f':
        if (parser->pos + 5 <= parser->end && 
            ngx_strncmp(parser->pos, "false", 5) == 0) {
            parser->current.type = JSON_TOKEN_FALSE;
            parser->pos += 5;
            return NGX_OK;
        }
        break;
        
    case 'n':
        if (parser->pos + 4 <= parser->end && 
            ngx_strncmp(parser->pos, "null", 4) == 0) {
            parser->current.type = JSON_TOKEN_NULL;
            parser->pos += 4;
            return NGX_OK;
        }
        break;
        
    case '-':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return json_parse_number(parser);
    }
    
    parser->current.type = JSON_TOKEN_ERROR;
    parser->error.data = (u_char *)"Unexpected character";
    parser->error.len = 20;
    return NGX_ERROR;
}

static cfml_value_t *
json_parse_object(cfml_json_parser_t *parser)
{
    cfml_value_t *obj;
    cfml_struct_t *s;
    ngx_str_t key;
    cfml_value_t *value;
    
    if (parser->depth >= parser->max_depth) {
        parser->error.data = (u_char *)"Maximum nesting depth exceeded";
        parser->error.len = 30;
        return NULL;
    }
    parser->depth++;
    
    obj = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
    if (obj == NULL) {
        return NULL;
    }
    obj->type = CFML_TYPE_STRUCT;
    obj->data.structure = cfml_struct_new(parser->pool);
    if (obj->data.structure == NULL) {
        return NULL;
    }
    s = obj->data.structure;
    
    /* Get next token after { */
    if (json_next_token(parser) != NGX_OK) {
        return NULL;
    }
    
    /* Empty object */
    if (parser->current.type == JSON_TOKEN_RBRACE) {
        parser->depth--;
        return obj;
    }
    
    while (1) {
        /* Expect string key */
        if (parser->current.type != JSON_TOKEN_STRING) {
            parser->error.data = (u_char *)"Expected string key in object";
            parser->error.len = 29;
            return NULL;
        }
        
        /* Copy key */
        key.len = parser->current.value.len;
        key.data = ngx_pnalloc(parser->pool, key.len + 1);
        if (key.data == NULL) {
            return NULL;
        }
        ngx_memcpy(key.data, parser->current.value.data, key.len);
        key.data[key.len] = '\0';
        
        /* Expect colon */
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
        if (parser->current.type != JSON_TOKEN_COLON) {
            parser->error.data = (u_char *)"Expected ':' after key";
            parser->error.len = 22;
            return NULL;
        }
        
        /* Parse value */
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
        value = json_parse_value(parser);
        if (value == NULL) {
            return NULL;
        }
        
        /* Add to struct */
        cfml_struct_set(s, &key, value);
        
        /* Next token */
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
        
        if (parser->current.type == JSON_TOKEN_RBRACE) {
            break;
        }
        
        if (parser->current.type != JSON_TOKEN_COMMA) {
            parser->error.data = (u_char *)"Expected ',' or '}' in object";
            parser->error.len = 29;
            return NULL;
        }
        
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
    }
    
    parser->depth--;
    return obj;
}

static cfml_value_t *
json_parse_array(cfml_json_parser_t *parser)
{
    cfml_value_t *arr;
    cfml_value_t *value;
    
    if (parser->depth >= parser->max_depth) {
        parser->error.data = (u_char *)"Maximum nesting depth exceeded";
        parser->error.len = 30;
        return NULL;
    }
    parser->depth++;
    
    arr = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
    if (arr == NULL) {
        return NULL;
    }
    arr->type = CFML_TYPE_ARRAY;
    arr->data.array = cfml_array_new(parser->pool, 16);
    if (arr->data.array == NULL) {
        return NULL;
    }
    
    /* Get next token after [ */
    if (json_next_token(parser) != NGX_OK) {
        return NULL;
    }
    
    /* Empty array */
    if (parser->current.type == JSON_TOKEN_RBRACKET) {
        parser->depth--;
        return arr;
    }
    
    while (1) {
        value = json_parse_value(parser);
        if (value == NULL) {
            return NULL;
        }
        
        cfml_array_append(arr->data.array, value);
        
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
        
        if (parser->current.type == JSON_TOKEN_RBRACKET) {
            break;
        }
        
        if (parser->current.type != JSON_TOKEN_COMMA) {
            parser->error.data = (u_char *)"Expected ',' or ']' in array";
            parser->error.len = 28;
            return NULL;
        }
        
        if (json_next_token(parser) != NGX_OK) {
            return NULL;
        }
    }
    
    parser->depth--;
    return arr;
}

static cfml_value_t *
json_parse_value(cfml_json_parser_t *parser)
{
    cfml_value_t *value;
    
    switch (parser->current.type) {
    case JSON_TOKEN_LBRACE:
        return json_parse_object(parser);
        
    case JSON_TOKEN_LBRACKET:
        return json_parse_array(parser);
        
    case JSON_TOKEN_STRING:
        value = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (value == NULL) {
            return NULL;
        }
        value->type = CFML_TYPE_STRING;
        value->data.string.len = parser->current.value.len;
        value->data.string.data = ngx_pnalloc(parser->pool, value->data.string.len + 1);
        if (value->data.string.data == NULL) {
            return NULL;
        }
        ngx_memcpy(value->data.string.data, parser->current.value.data, 
                   value->data.string.len);
        value->data.string.data[value->data.string.len] = '\0';
        return value;
        
    case JSON_TOKEN_NUMBER:
        value = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (value == NULL) {
            return NULL;
        }
        /* Check if it's an integer */
        if (parser->current.number == floor(parser->current.number) &&
            parser->current.number >= INT64_MIN && 
            parser->current.number <= INT64_MAX) {
            value->type = CFML_TYPE_INTEGER;
            value->data.integer = (int64_t)parser->current.number;
        } else {
            value->type = CFML_TYPE_FLOAT;
            value->data.floating = parser->current.number;
        }
        return value;
        
    case JSON_TOKEN_TRUE:
        value = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (value == NULL) {
            return NULL;
        }
        value->type = CFML_TYPE_BOOLEAN;
        value->data.boolean = 1;
        return value;
        
    case JSON_TOKEN_FALSE:
        value = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (value == NULL) {
            return NULL;
        }
        value->type = CFML_TYPE_BOOLEAN;
        value->data.boolean = 0;
        return value;
        
    case JSON_TOKEN_NULL:
        value = ngx_pcalloc(parser->pool, sizeof(cfml_value_t));
        if (value == NULL) {
            return NULL;
        }
        value->type = CFML_TYPE_NULL;
        return value;
        
    default:
        parser->error.data = (u_char *)"Unexpected token";
        parser->error.len = 16;
        return NULL;
    }
}

cfml_value_t *
cfml_json_parse(ngx_pool_t *pool, ngx_str_t *json)
{
    return cfml_json_parse_ex(pool, json, JSON_MAX_DEPTH, NULL);
}

cfml_value_t *
cfml_json_parse_ex(ngx_pool_t *pool, ngx_str_t *json, ngx_uint_t max_depth, 
                   ngx_str_t *error)
{
    cfml_json_parser_t parser;
    cfml_value_t *result;
    
    if (json == NULL || json->len == 0) {
        if (error) {
            error->data = (u_char *)"Empty JSON input";
            error->len = 16;
        }
        return NULL;
    }
    
    ngx_memzero(&parser, sizeof(cfml_json_parser_t));
    parser.pool = pool;
    parser.pos = json->data;
    parser.end = json->data + json->len;
    parser.max_depth = max_depth > 0 ? max_depth : JSON_MAX_DEPTH;
    
    if (json_next_token(&parser) != NGX_OK) {
        if (error) {
            *error = parser.error;
        }
        return NULL;
    }
    
    result = json_parse_value(&parser);
    
    if (result == NULL && error) {
        *error = parser.error;
    }
    
    return result;
}

ngx_int_t
cfml_json_validate(ngx_str_t *json)
{
    ngx_pool_t *temp_pool;
    cfml_value_t *result;
    
    temp_pool = ngx_create_pool(4096, ngx_cycle->log);
    if (temp_pool == NULL) {
        return NGX_ERROR;
    }
    
    result = cfml_json_parse(temp_pool, json);
    ngx_destroy_pool(temp_pool);
    
    return result != NULL ? NGX_OK : NGX_ERROR;
}

/*
 * JSON Serializer Implementation
 */

static ngx_int_t
json_write_raw(cfml_json_writer_t *writer, u_char *data, size_t len)
{
    size_t available;
    size_t to_write;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    
    while (len > 0) {
        if (writer->current_buf == NULL || 
            writer->current_buf->last >= writer->current_buf->end) {
            /* Allocate new buffer */
            b = ngx_create_temp_buf(writer->pool, JSON_INITIAL_BUF_SIZE);
            if (b == NULL) {
                return NGX_ERROR;
            }
            
            cl = ngx_alloc_chain_link(writer->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }
            
            cl->buf = b;
            cl->next = NULL;
            
            if (writer->last) {
                writer->last->next = cl;
            } else {
                writer->chain = cl;
            }
            writer->last = cl;
            writer->current_buf = b;
        }
        
        available = writer->current_buf->end - writer->current_buf->last;
        to_write = len < available ? len : available;
        
        ngx_memcpy(writer->current_buf->last, data, to_write);
        writer->current_buf->last += to_write;
        writer->total_size += to_write;
        
        data += to_write;
        len -= to_write;
    }
    
    return NGX_OK;
}

static ngx_int_t
json_write_char(cfml_json_writer_t *writer, u_char c)
{
    return json_write_raw(writer, &c, 1);
}

static ngx_int_t
json_write_indent(cfml_json_writer_t *writer, ngx_uint_t depth)
{
    ngx_uint_t i, spaces;
    
    if (!writer->options.pretty) {
        return NGX_OK;
    }
    
    if (json_write_char(writer, '\n') != NGX_OK) {
        return NGX_ERROR;
    }
    
    spaces = depth * writer->options.indent_size;
    for (i = 0; i < spaces; i++) {
        if (json_write_char(writer, ' ') != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    return NGX_OK;
}

static ngx_int_t
json_write_escaped_string(cfml_json_writer_t *writer, ngx_str_t *str)
{
    u_char *p, *end;
    u_char c;
    u_char buf[8];
    
    if (json_write_char(writer, '"') != NGX_OK) {
        return NGX_ERROR;
    }
    
    p = str->data;
    end = str->data + str->len;
    
    while (p < end) {
        c = *p++;
        
        switch (c) {
        case '"':
            if (json_write_raw(writer, (u_char *)"\\\"", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\\':
            if (json_write_raw(writer, (u_char *)"\\\\", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\b':
            if (json_write_raw(writer, (u_char *)"\\b", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\f':
            if (json_write_raw(writer, (u_char *)"\\f", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\n':
            if (json_write_raw(writer, (u_char *)"\\n", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\r':
            if (json_write_raw(writer, (u_char *)"\\r", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        case '\t':
            if (json_write_raw(writer, (u_char *)"\\t", 2) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        default:
            if (c < 0x20) {
                /* Control character - escape as \u00XX */
                ngx_sprintf(buf, "\\u%04xd", (unsigned)c);
                if (json_write_raw(writer, buf, 6) != NGX_OK) {
                    return NGX_ERROR;
                }
            } else {
                if (json_write_char(writer, c) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
            break;
        }
    }
    
    return json_write_char(writer, '"');
}

static ngx_int_t
json_serialize_struct(cfml_json_writer_t *writer, cfml_struct_t *s, ngx_uint_t depth)
{
    cfml_struct_entry_t *entries;
    ngx_uint_t i;
    ngx_int_t first = 1;
    
    if (json_write_char(writer, '{') != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (s == NULL || s->entries->nelts == 0) {
        return json_write_char(writer, '}');
    }
    
    entries = s->entries->elts;
    
    for (i = 0; i < s->entries->nelts; i++) {
        if (!writer->options.serialize_null && 
            entries[i].value && entries[i].value->type == CFML_TYPE_NULL) {
            continue;
        }
        
        if (!first) {
            if (json_write_char(writer, ',') != NGX_OK) {
                return NGX_ERROR;
            }
        }
        first = 0;
        
        if (json_write_indent(writer, depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (json_write_escaped_string(writer, &entries[i].key) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (json_write_char(writer, ':') != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (writer->options.pretty) {
            if (json_write_char(writer, ' ') != NGX_OK) {
                return NGX_ERROR;
            }
        }
        
        if (json_serialize_value(writer, entries[i].value, depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    if (json_write_indent(writer, depth) != NGX_OK) {
        return NGX_ERROR;
    }
    
    return json_write_char(writer, '}');
}

static ngx_int_t
json_serialize_array(cfml_json_writer_t *writer, cfml_array_t *arr, ngx_uint_t depth)
{
    cfml_value_t **items;
    ngx_uint_t i;
    
    if (json_write_char(writer, '[') != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (arr == NULL || arr->items->nelts == 0) {
        return json_write_char(writer, ']');
    }
    
    items = arr->items->elts;
    
    for (i = 0; i < arr->items->nelts; i++) {
        if (i > 0) {
            if (json_write_char(writer, ',') != NGX_OK) {
                return NGX_ERROR;
            }
        }
        
        if (json_write_indent(writer, depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (json_serialize_value(writer, items[i], depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    if (json_write_indent(writer, depth) != NGX_OK) {
        return NGX_ERROR;
    }
    
    return json_write_char(writer, ']');
}

static ngx_int_t
json_serialize_query(cfml_json_writer_t *writer, cfml_query_t *q, ngx_uint_t depth)
{
    ngx_uint_t i, j, column_count;
    ngx_int_t first_row = 1;
    cfml_query_column_t *columns;
    cfml_value_t **col_data;
    
    /* Serialize as array of objects */
    if (json_write_char(writer, '[') != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (q == NULL || q->row_count == 0 || q->columns == NULL) {
        return json_write_char(writer, ']');
    }
    
    columns = q->columns->elts;
    column_count = q->columns->nelts;
    
    for (i = 0; i < q->row_count; i++) {
        if (!first_row) {
            if (json_write_char(writer, ',') != NGX_OK) {
                return NGX_ERROR;
            }
        }
        first_row = 0;
        
        if (json_write_indent(writer, depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (json_write_char(writer, '{') != NGX_OK) {
            return NGX_ERROR;
        }
        
        for (j = 0; j < column_count; j++) {
            if (j > 0) {
                if (json_write_char(writer, ',') != NGX_OK) {
                    return NGX_ERROR;
                }
            }
            
            if (json_write_indent(writer, depth + 2) != NGX_OK) {
                return NGX_ERROR;
            }
            
            if (json_write_escaped_string(writer, &columns[j].name) != NGX_OK) {
                return NGX_ERROR;
            }
            
            if (json_write_char(writer, ':') != NGX_OK) {
                return NGX_ERROR;
            }
            
            if (writer->options.pretty) {
                if (json_write_char(writer, ' ') != NGX_OK) {
                    return NGX_ERROR;
                }
            }
            
            /* Get value from column data array */
            col_data = columns[j].data->elts;
            if (i < columns[j].data->nelts) {
                if (json_serialize_value(writer, col_data[i], depth + 2) != NGX_OK) {
                    return NGX_ERROR;
                }
            } else {
                if (json_write_raw(writer, (u_char *)"null", 4) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }
        
        if (json_write_indent(writer, depth + 1) != NGX_OK) {
            return NGX_ERROR;
        }
        
        if (json_write_char(writer, '}') != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    if (json_write_indent(writer, depth) != NGX_OK) {
        return NGX_ERROR;
    }
    
    return json_write_char(writer, ']');
}

static ngx_int_t
json_serialize_value(cfml_json_writer_t *writer, cfml_value_t *value, ngx_uint_t depth)
{
    u_char buf[64];
    size_t len;
    
    if (depth > writer->options.max_depth) {
        return json_write_raw(writer, (u_char *)"null", 4);
    }
    
    if (value == NULL) {
        return json_write_raw(writer, (u_char *)"null", 4);
    }
    
    switch (value->type) {
    case CFML_TYPE_NULL:
        return json_write_raw(writer, (u_char *)"null", 4);
        
    case CFML_TYPE_BOOLEAN:
        if (value->data.boolean) {
            return json_write_raw(writer, (u_char *)"true", 4);
        } else {
            return json_write_raw(writer, (u_char *)"false", 5);
        }
        
    case CFML_TYPE_INTEGER:
        len = ngx_sprintf(buf, "%L", value->data.integer) - buf;
        return json_write_raw(writer, buf, len);
        
    case CFML_TYPE_FLOAT:
        if (isnan(value->data.floating) || isinf(value->data.floating)) {
            return json_write_raw(writer, (u_char *)"null", 4);
        }
        len = ngx_sprintf(buf, "%.15g", value->data.floating) - buf;
        return json_write_raw(writer, buf, len);
        
    case CFML_TYPE_STRING:
        return json_write_escaped_string(writer, &value->data.string);
        
    case CFML_TYPE_ARRAY:
        return json_serialize_array(writer, value->data.array, depth);
        
    case CFML_TYPE_STRUCT:
        return json_serialize_struct(writer, value->data.structure, depth);
        
    case CFML_TYPE_QUERY:
        return json_serialize_query(writer, value->data.query, depth);
        
    case CFML_TYPE_DATE:
        /* ISO 8601 format */
        len = strftime((char *)buf, sizeof(buf), "\"%Y-%m-%dT%H:%M:%S\"", 
                       localtime(&value->data.date.time));
        return json_write_raw(writer, buf, len);
        
    case CFML_TYPE_BINARY:
        /* Base64 encode binary data */
        /* TODO: Implement base64 encoding */
        return json_write_raw(writer, (u_char *)"null", 4);
        
    default:
        return json_write_raw(writer, (u_char *)"null", 4);
    }
}

cfml_json_writer_t *
cfml_json_writer_create(ngx_pool_t *pool, cfml_json_options_t *options)
{
    cfml_json_writer_t *writer;
    
    writer = ngx_pcalloc(pool, sizeof(cfml_json_writer_t));
    if (writer == NULL) {
        return NULL;
    }
    
    writer->pool = pool;
    
    if (options) {
        writer->options = *options;
    } else {
        writer->options.indent_size = 2;
        writer->options.max_depth = JSON_MAX_DEPTH;
        writer->options.serialize_null = 1;
    }
    
    if (writer->options.max_depth == 0) {
        writer->options.max_depth = JSON_MAX_DEPTH;
    }
    
    return writer;
}

ngx_int_t
cfml_json_write_value(cfml_json_writer_t *writer, cfml_value_t *value)
{
    return json_serialize_value(writer, value, 0);
}

ngx_chain_t *
cfml_json_writer_get_chain(cfml_json_writer_t *writer)
{
    if (writer->current_buf) {
        writer->current_buf->last_buf = 1;
    }
    return writer->chain;
}

ngx_str_t *
cfml_json_writer_get_string(cfml_json_writer_t *writer)
{
    ngx_str_t *result;
    ngx_chain_t *cl;
    u_char *p;
    
    result = ngx_pcalloc(writer->pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->len = writer->total_size;
    result->data = ngx_pnalloc(writer->pool, result->len + 1);
    if (result->data == NULL) {
        return NULL;
    }
    
    p = result->data;
    for (cl = writer->chain; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }
    *p = '\0';
    
    return result;
}

ngx_str_t *
cfml_json_serialize(ngx_pool_t *pool, cfml_value_t *value)
{
    return cfml_json_serialize_ex(pool, value, NULL);
}

ngx_str_t *
cfml_json_serialize_ex(ngx_pool_t *pool, cfml_value_t *value, 
                        cfml_json_options_t *options)
{
    cfml_json_writer_t *writer;
    
    writer = cfml_json_writer_create(pool, options);
    if (writer == NULL) {
        return NULL;
    }
    
    if (cfml_json_write_value(writer, value) != NGX_OK) {
        return NULL;
    }
    
    return cfml_json_writer_get_string(writer);
}

/*
 * CFML Built-in Function Implementations
 */

cfml_value_t *
cfml_func_serializejson(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_value_t *result;
    cfml_json_options_t options;
    ngx_str_t *json;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    argv = args->elts;
    
    ngx_memzero(&options, sizeof(options));
    options.indent_size = 2;
    options.max_depth = JSON_MAX_DEPTH;
    options.serialize_null = 1;
    
    json = cfml_json_serialize_ex(ctx->pool, argv[0], &options);
    if (json == NULL) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    if (result == NULL) {
        return NULL;
    }
    result->type = CFML_TYPE_STRING;
    result->data.string = *json;
    
    return result;
}

cfml_value_t *
cfml_func_deserializejson(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t json;
    ngx_str_t error;
    cfml_value_t *result;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    json = argv[0]->data.string;
    ngx_memzero(&error, sizeof(error));
    
    result = cfml_json_parse_ex(ctx->pool, &json, JSON_MAX_DEPTH, &error);
    
    if (result == NULL) {
        /* Return empty struct on error - could also throw */
        return cfml_create_struct(ctx->pool);
    }
    
    return result;
}

cfml_value_t *
cfml_func_isjson(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_value_t *result;
    ngx_str_t json;
    
    result = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    if (result == NULL) {
        return NULL;
    }
    result->type = CFML_TYPE_BOOLEAN;
    result->data.boolean = 0;
    
    if (args == NULL || args->nelts < 1) {
        return result;
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return result;
    }
    
    json = argv[0]->data.string;
    result->data.boolean = (cfml_json_validate(&json) == NGX_OK);
    
    return result;
}

cfml_value_t *
cfml_func_jsonparse(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_func_deserializejson(ctx, args);
}

cfml_value_t *
cfml_func_jsonserialize(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_func_serializejson(ctx, args);
}

/*
 * JSON Path Implementation (basic)
 */

cfml_value_t *
cfml_json_path_get(cfml_value_t *root, ngx_str_t *path)
{
    u_char *p, *end, *start;
    cfml_value_t *current = root;
    ngx_str_t key;
    ngx_int_t index;
    
    if (root == NULL || path == NULL || path->len == 0) {
        return NULL;
    }
    
    p = path->data;
    end = path->data + path->len;
    
    /* Skip leading $ */
    if (*p == '$') {
        p++;
    }
    
    while (p < end && current != NULL) {
        if (*p == '.') {
            p++;
            start = p;
            
            /* Read key name */
            while (p < end && *p != '.' && *p != '[') {
                p++;
            }
            
            if (current->type != CFML_TYPE_STRUCT) {
                return NULL;
            }
            
            key.data = start;
            key.len = p - start;
            current = cfml_struct_get(current->data.structure, &key);
            
        } else if (*p == '[') {
            p++;
            start = p;
            
            /* Read index or key */
            while (p < end && *p != ']') {
                p++;
            }
            
            if (*start >= '0' && *start <= '9') {
                /* Array index */
                if (current->type != CFML_TYPE_ARRAY) {
                    return NULL;
                }
                index = ngx_atoi(start, p - start);
                if (index < 0 || (ngx_uint_t)index >= cfml_array_len(current->data.array)) {
                    return NULL;
                }
                current = cfml_array_get(current->data.array, index);
            } else {
                /* String key (quoted) */
                if (*start == '"' || *start == '\'') {
                    start++;
                    key.data = start;
                    key.len = p - start - 1;
                } else {
                    key.data = start;
                    key.len = p - start;
                }
                
                if (current->type != CFML_TYPE_STRUCT) {
                    return NULL;
                }
                current = cfml_struct_get(current->data.structure, &key);
            }
            
            if (p < end && *p == ']') {
                p++;
            }
        } else {
            p++;
        }
    }
    
    return current;
}

ngx_int_t
cfml_json_path_set(cfml_value_t *root, ngx_str_t *path, cfml_value_t *value)
{
    /* TODO: Implement JSON path set */
    (void)root;
    (void)path;
    (void)value;
    return NGX_ERROR;
}

/* Streaming writer methods */
ngx_int_t cfml_json_write_null(cfml_json_writer_t *writer) {
    return json_write_raw(writer, (u_char *)"null", 4);
}

ngx_int_t cfml_json_write_bool(cfml_json_writer_t *writer, ngx_int_t value) {
    if (value) {
        return json_write_raw(writer, (u_char *)"true", 4);
    }
    return json_write_raw(writer, (u_char *)"false", 5);
}

ngx_int_t cfml_json_write_number(cfml_json_writer_t *writer, double value) {
    u_char buf[64];
    size_t len;
    
    if (isnan(value) || isinf(value)) {
        return json_write_raw(writer, (u_char *)"null", 4);
    }
    len = ngx_sprintf(buf, "%.15g", value) - buf;
    return json_write_raw(writer, buf, len);
}

ngx_int_t cfml_json_write_integer(cfml_json_writer_t *writer, int64_t value) {
    u_char buf[32];
    size_t len;
    len = ngx_sprintf(buf, "%L", value) - buf;
    return json_write_raw(writer, buf, len);
}

ngx_int_t cfml_json_write_string(cfml_json_writer_t *writer, ngx_str_t *value) {
    return json_write_escaped_string(writer, value);
}

ngx_int_t cfml_json_write_object_start(cfml_json_writer_t *writer) {
    writer->depth++;
    writer->need_comma = 0;
    return json_write_char(writer, '{');
}

ngx_int_t cfml_json_write_object_key(cfml_json_writer_t *writer, ngx_str_t *key) {
    if (writer->need_comma) {
        if (json_write_char(writer, ',') != NGX_OK) {
            return NGX_ERROR;
        }
    }
    writer->need_comma = 1;
    
    if (json_write_indent(writer, writer->depth) != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (json_write_escaped_string(writer, key) != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (json_write_char(writer, ':') != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (writer->options.pretty) {
        return json_write_char(writer, ' ');
    }
    
    return NGX_OK;
}

ngx_int_t cfml_json_write_object_end(cfml_json_writer_t *writer) {
    writer->depth--;
    if (json_write_indent(writer, writer->depth) != NGX_OK) {
        return NGX_ERROR;
    }
    writer->need_comma = 1;
    return json_write_char(writer, '}');
}

ngx_int_t cfml_json_write_array_start(cfml_json_writer_t *writer) {
    writer->depth++;
    writer->need_comma = 0;
    return json_write_char(writer, '[');
}

ngx_int_t cfml_json_write_array_end(cfml_json_writer_t *writer) {
    writer->depth--;
    if (json_write_indent(writer, writer->depth) != NGX_OK) {
        return NGX_ERROR;
    }
    writer->need_comma = 1;
    return json_write_char(writer, ']');
}
