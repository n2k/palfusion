/*
 * CFML MessagePack - Binary serialization implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_msgpack.h"
#include "cfml_variables.h"

/* MessagePack format markers */
#define MP_FIXMAP      0x80
#define MP_FIXARRAY    0x90
#define MP_FIXSTR      0xa0
#define MP_NIL         0xc0
#define MP_FALSE       0xc2
#define MP_TRUE        0xc3
#define MP_BIN8        0xc4
#define MP_BIN16       0xc5
#define MP_BIN32       0xc6
#define MP_FLOAT32     0xca
#define MP_FLOAT64     0xcb
#define MP_UINT8       0xcc
#define MP_UINT16      0xcd
#define MP_UINT32      0xce
#define MP_UINT64      0xcf
#define MP_INT8        0xd0
#define MP_INT16       0xd1
#define MP_INT32       0xd2
#define MP_INT64       0xd3
#define MP_STR8        0xd9
#define MP_STR16       0xda
#define MP_STR32       0xdb
#define MP_ARRAY16     0xdc
#define MP_ARRAY32     0xdd
#define MP_MAP16       0xde
#define MP_MAP32       0xdf

#define MP_BUF_SIZE    65536

typedef struct {
    u_char      *buf;
    size_t      size;
    size_t      pos;
    ngx_pool_t  *pool;
} mp_encoder_t;

static ngx_int_t mp_encode_value(mp_encoder_t *enc, cfml_value_t *value);

static ngx_int_t
mp_ensure_space(mp_encoder_t *enc, size_t needed)
{
    if (enc->pos + needed > enc->size) {
        size_t new_size = enc->size * 2;
        while (new_size < enc->pos + needed) {
            new_size *= 2;
        }
        u_char *new_buf = ngx_pnalloc(enc->pool, new_size);
        if (new_buf == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(new_buf, enc->buf, enc->pos);
        enc->buf = new_buf;
        enc->size = new_size;
    }
    return NGX_OK;
}

static ngx_int_t
mp_encode_nil(mp_encoder_t *enc)
{
    if (mp_ensure_space(enc, 1) != NGX_OK) return NGX_ERROR;
    enc->buf[enc->pos++] = MP_NIL;
    return NGX_OK;
}

static ngx_int_t
mp_encode_bool(mp_encoder_t *enc, ngx_int_t val)
{
    if (mp_ensure_space(enc, 1) != NGX_OK) return NGX_ERROR;
    enc->buf[enc->pos++] = val ? MP_TRUE : MP_FALSE;
    return NGX_OK;
}

static ngx_int_t
mp_encode_int(mp_encoder_t *enc, int64_t val)
{
    if (mp_ensure_space(enc, 9) != NGX_OK) return NGX_ERROR;
    
    if (val >= 0 && val <= 127) {
        enc->buf[enc->pos++] = (u_char)val;
    } else if (val >= -32 && val < 0) {
        enc->buf[enc->pos++] = (u_char)(0xe0 | (val & 0x1f));
    } else if (val >= 0 && val <= 0xff) {
        enc->buf[enc->pos++] = MP_UINT8;
        enc->buf[enc->pos++] = (u_char)val;
    } else if (val >= 0 && val <= 0xffff) {
        enc->buf[enc->pos++] = MP_UINT16;
        enc->buf[enc->pos++] = (val >> 8) & 0xff;
        enc->buf[enc->pos++] = val & 0xff;
    } else if (val >= 0 && val <= 0xffffffff) {
        enc->buf[enc->pos++] = MP_UINT32;
        enc->buf[enc->pos++] = (val >> 24) & 0xff;
        enc->buf[enc->pos++] = (val >> 16) & 0xff;
        enc->buf[enc->pos++] = (val >> 8) & 0xff;
        enc->buf[enc->pos++] = val & 0xff;
    } else {
        enc->buf[enc->pos++] = val >= 0 ? MP_UINT64 : MP_INT64;
        enc->buf[enc->pos++] = (val >> 56) & 0xff;
        enc->buf[enc->pos++] = (val >> 48) & 0xff;
        enc->buf[enc->pos++] = (val >> 40) & 0xff;
        enc->buf[enc->pos++] = (val >> 32) & 0xff;
        enc->buf[enc->pos++] = (val >> 24) & 0xff;
        enc->buf[enc->pos++] = (val >> 16) & 0xff;
        enc->buf[enc->pos++] = (val >> 8) & 0xff;
        enc->buf[enc->pos++] = val & 0xff;
    }
    return NGX_OK;
}

static ngx_int_t
mp_encode_double(mp_encoder_t *enc, double val)
{
    union { double d; uint64_t i; } u;
    if (mp_ensure_space(enc, 9) != NGX_OK) return NGX_ERROR;
    
    u.d = val;
    enc->buf[enc->pos++] = MP_FLOAT64;
    enc->buf[enc->pos++] = (u.i >> 56) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 48) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 40) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 32) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 24) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 16) & 0xff;
    enc->buf[enc->pos++] = (u.i >> 8) & 0xff;
    enc->buf[enc->pos++] = u.i & 0xff;
    return NGX_OK;
}

static ngx_int_t
mp_encode_str(mp_encoder_t *enc, ngx_str_t *str)
{
    size_t len = str->len;
    
    if (mp_ensure_space(enc, 5 + len) != NGX_OK) return NGX_ERROR;
    
    if (len <= 31) {
        enc->buf[enc->pos++] = MP_FIXSTR | len;
    } else if (len <= 0xff) {
        enc->buf[enc->pos++] = MP_STR8;
        enc->buf[enc->pos++] = len;
    } else if (len <= 0xffff) {
        enc->buf[enc->pos++] = MP_STR16;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    } else {
        enc->buf[enc->pos++] = MP_STR32;
        enc->buf[enc->pos++] = (len >> 24) & 0xff;
        enc->buf[enc->pos++] = (len >> 16) & 0xff;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    }
    
    ngx_memcpy(enc->buf + enc->pos, str->data, len);
    enc->pos += len;
    return NGX_OK;
}

static ngx_int_t
mp_encode_array(mp_encoder_t *enc, cfml_array_t *arr)
{
    ngx_uint_t len = arr->items->nelts;
    cfml_value_t **items;
    ngx_uint_t i;
    
    if (mp_ensure_space(enc, 5) != NGX_OK) return NGX_ERROR;
    
    if (len <= 15) {
        enc->buf[enc->pos++] = MP_FIXARRAY | len;
    } else if (len <= 0xffff) {
        enc->buf[enc->pos++] = MP_ARRAY16;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    } else {
        enc->buf[enc->pos++] = MP_ARRAY32;
        enc->buf[enc->pos++] = (len >> 24) & 0xff;
        enc->buf[enc->pos++] = (len >> 16) & 0xff;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    }
    
    items = arr->items->elts;
    for (i = 0; i < len; i++) {
        if (mp_encode_value(enc, items[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t
mp_encode_map(mp_encoder_t *enc, cfml_struct_t *s)
{
    ngx_uint_t len = s->entries->nelts;
    cfml_struct_entry_t *entries;
    ngx_uint_t i;
    
    if (mp_ensure_space(enc, 5) != NGX_OK) return NGX_ERROR;
    
    if (len <= 15) {
        enc->buf[enc->pos++] = MP_FIXMAP | len;
    } else if (len <= 0xffff) {
        enc->buf[enc->pos++] = MP_MAP16;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    } else {
        enc->buf[enc->pos++] = MP_MAP32;
        enc->buf[enc->pos++] = (len >> 24) & 0xff;
        enc->buf[enc->pos++] = (len >> 16) & 0xff;
        enc->buf[enc->pos++] = (len >> 8) & 0xff;
        enc->buf[enc->pos++] = len & 0xff;
    }
    
    entries = s->entries->elts;
    for (i = 0; i < len; i++) {
        if (mp_encode_str(enc, &entries[i].key) != NGX_OK) {
            return NGX_ERROR;
        }
        if (mp_encode_value(enc, entries[i].value) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t
mp_encode_value(mp_encoder_t *enc, cfml_value_t *value)
{
    if (value == NULL) {
        return mp_encode_nil(enc);
    }
    
    switch (value->type) {
    case CFML_TYPE_NULL:
        return mp_encode_nil(enc);
    case CFML_TYPE_BOOLEAN:
        return mp_encode_bool(enc, value->data.boolean);
    case CFML_TYPE_INTEGER:
        return mp_encode_int(enc, value->data.integer);
    case CFML_TYPE_FLOAT:
        return mp_encode_double(enc, value->data.floating);
    case CFML_TYPE_STRING:
        return mp_encode_str(enc, &value->data.string);
    case CFML_TYPE_ARRAY:
        return mp_encode_array(enc, value->data.array);
    case CFML_TYPE_STRUCT:
        return mp_encode_map(enc, value->data.structure);
    default:
        return mp_encode_nil(enc);
    }
}

ngx_str_t *
cfml_msgpack_encode(ngx_pool_t *pool, cfml_value_t *value)
{
    mp_encoder_t enc;
    ngx_str_t *result;
    
    enc.pool = pool;
    enc.size = MP_BUF_SIZE;
    enc.pos = 0;
    enc.buf = ngx_pnalloc(pool, enc.size);
    if (enc.buf == NULL) {
        return NULL;
    }
    
    if (mp_encode_value(&enc, value) != NGX_OK) {
        return NULL;
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->data = enc.buf;
    result->len = enc.pos;
    return result;
}

cfml_value_t *
cfml_msgpack_decode(ngx_pool_t *pool, ngx_str_t *data)
{
    /* TODO: Implement MessagePack decoder */
    (void)pool;
    (void)data;
    return NULL;
}

cfml_value_t *
cfml_func_msgpackencode(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *result;
    cfml_value_t *val;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    result = cfml_msgpack_encode(ctx->pool, argv[0]);
    
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* Return as binary */
    val = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    if (val == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    val->type = CFML_TYPE_BINARY;
    val->data.binary.data = result->data;
    val->data.binary.len = result->len;
    return val;
}

cfml_value_t *
cfml_func_msgpackdecode(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t data;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type == CFML_TYPE_BINARY) {
        data.data = argv[0]->data.binary.data;
        data.len = argv[0]->data.binary.len;
    } else if (argv[0]->type == CFML_TYPE_STRING) {
        data = argv[0]->data.string;
    } else {
        return cfml_create_null(ctx->pool);
    }
    
    return cfml_msgpack_decode(ctx->pool, &data);
}
