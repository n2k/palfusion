/*
 * CFML JSON - Native JSON support
 * SerializeJSON, DeserializeJSON, IsJSON, and streaming
 */

#ifndef _CFML_JSON_H_
#define _CFML_JSON_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* JSON token types for parser */
typedef enum {
    JSON_TOKEN_NONE = 0,
    JSON_TOKEN_LBRACE,          /* { */
    JSON_TOKEN_RBRACE,          /* } */
    JSON_TOKEN_LBRACKET,        /* [ */
    JSON_TOKEN_RBRACKET,        /* ] */
    JSON_TOKEN_COLON,           /* : */
    JSON_TOKEN_COMMA,           /* , */
    JSON_TOKEN_STRING,
    JSON_TOKEN_NUMBER,
    JSON_TOKEN_TRUE,
    JSON_TOKEN_FALSE,
    JSON_TOKEN_NULL,
    JSON_TOKEN_EOF,
    JSON_TOKEN_ERROR
} cfml_json_token_type_t;

/* JSON token */
typedef struct {
    cfml_json_token_type_t  type;
    ngx_str_t               value;
    double                  number;
} cfml_json_token_t;

/* JSON parser context */
typedef struct {
    ngx_pool_t              *pool;
    u_char                  *pos;
    u_char                  *end;
    cfml_json_token_t       current;
    ngx_str_t               error;
    ngx_uint_t              depth;
    ngx_uint_t              max_depth;
} cfml_json_parser_t;

/* JSON serialization options */
typedef struct {
    unsigned                pretty:1;           /* Pretty print with indentation */
    unsigned                sort_keys:1;        /* Sort struct keys alphabetically */
    unsigned                escape_unicode:1;   /* Escape non-ASCII as \uXXXX */
    unsigned                serialize_null:1;   /* Include null values */
    ngx_uint_t              indent_size;        /* Spaces per indent level (default 2) */
    ngx_uint_t              max_depth;          /* Maximum nesting depth */
} cfml_json_options_t;

/* JSON streaming writer for large documents */
typedef struct {
    ngx_pool_t              *pool;
    ngx_chain_t             *chain;
    ngx_chain_t             *last;
    ngx_buf_t               *current_buf;
    size_t                  total_size;
    cfml_json_options_t     options;
    ngx_uint_t              depth;
    unsigned                need_comma:1;
} cfml_json_writer_t;

/*
 * Core JSON functions
 */

/* Parse JSON string to CFML value */
cfml_value_t *cfml_json_parse(ngx_pool_t *pool, ngx_str_t *json);

/* Parse with options */
cfml_value_t *cfml_json_parse_ex(ngx_pool_t *pool, ngx_str_t *json, 
                                  ngx_uint_t max_depth, ngx_str_t *error);

/* Serialize CFML value to JSON string */
ngx_str_t *cfml_json_serialize(ngx_pool_t *pool, cfml_value_t *value);

/* Serialize with options */
ngx_str_t *cfml_json_serialize_ex(ngx_pool_t *pool, cfml_value_t *value,
                                   cfml_json_options_t *options);

/* Validate JSON string */
ngx_int_t cfml_json_validate(ngx_str_t *json);

/* Get parse error message */
ngx_str_t *cfml_json_get_error(cfml_json_parser_t *parser);

/*
 * Streaming JSON writer for large documents
 */

/* Initialize streaming writer */
cfml_json_writer_t *cfml_json_writer_create(ngx_pool_t *pool, 
                                             cfml_json_options_t *options);

/* Write primitives */
ngx_int_t cfml_json_write_null(cfml_json_writer_t *writer);
ngx_int_t cfml_json_write_bool(cfml_json_writer_t *writer, ngx_int_t value);
ngx_int_t cfml_json_write_number(cfml_json_writer_t *writer, double value);
ngx_int_t cfml_json_write_integer(cfml_json_writer_t *writer, int64_t value);
ngx_int_t cfml_json_write_string(cfml_json_writer_t *writer, ngx_str_t *value);

/* Write containers */
ngx_int_t cfml_json_write_object_start(cfml_json_writer_t *writer);
ngx_int_t cfml_json_write_object_key(cfml_json_writer_t *writer, ngx_str_t *key);
ngx_int_t cfml_json_write_object_end(cfml_json_writer_t *writer);
ngx_int_t cfml_json_write_array_start(cfml_json_writer_t *writer);
ngx_int_t cfml_json_write_array_end(cfml_json_writer_t *writer);

/* Write CFML value (recursive) */
ngx_int_t cfml_json_write_value(cfml_json_writer_t *writer, cfml_value_t *value);

/* Get output chain */
ngx_chain_t *cfml_json_writer_get_chain(cfml_json_writer_t *writer);

/* Get output as string (for smaller documents) */
ngx_str_t *cfml_json_writer_get_string(cfml_json_writer_t *writer);

/*
 * JSON Path support (basic)
 */

/* Get value at JSON path (e.g., "$.users[0].name") */
cfml_value_t *cfml_json_path_get(cfml_value_t *root, ngx_str_t *path);

/* Set value at JSON path */
ngx_int_t cfml_json_path_set(cfml_value_t *root, ngx_str_t *path, 
                              cfml_value_t *value);

/*
 * CFML built-in function implementations
 */

/* SerializeJSON(var [, serializeQueryByColumns [, useSecureJSONPrefix [, useCustomSerializer]]]) */
cfml_value_t *cfml_func_serializejson(cfml_context_t *ctx, ngx_array_t *args);

/* DeserializeJSON(json [, strictMapping [, useCustomSerializer]]) */
cfml_value_t *cfml_func_deserializejson(cfml_context_t *ctx, ngx_array_t *args);

/* IsJSON(string) */
cfml_value_t *cfml_func_isjson(cfml_context_t *ctx, ngx_array_t *args);

/* JSONParse(json) - alias for DeserializeJSON */
cfml_value_t *cfml_func_jsonparse(cfml_context_t *ctx, ngx_array_t *args);

/* JSONSerialize(var) - alias for SerializeJSON */
cfml_value_t *cfml_func_jsonserialize(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_JSON_H_ */
