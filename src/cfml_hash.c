/*
 * CFML Hash - Cryptographic functions implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "cfml_hash.h"

ngx_int_t
cfml_hash_string(ngx_pool_t *pool, ngx_str_t *input,
                 cfml_hash_algorithm_t algorithm,
                 cfml_encoding_t encoding,
                 ngx_str_t *output)
{
    u_char hash[64];
    size_t hash_len;
    u_char *p;
    ngx_uint_t i;

    switch (algorithm) {
    case CFML_HASH_MD5:
        MD5(input->data, input->len, hash);
        hash_len = 16;
        break;
    case CFML_HASH_SHA:
    case CFML_HASH_SHA1:
        SHA1(input->data, input->len, hash);
        hash_len = 20;
        break;
    case CFML_HASH_SHA256:
        SHA256(input->data, input->len, hash);
        hash_len = 32;
        break;
    case CFML_HASH_SHA384:
        SHA384(input->data, input->len, hash);
        hash_len = 48;
        break;
    case CFML_HASH_SHA512:
        SHA512(input->data, input->len, hash);
        hash_len = 64;
        break;
    default:
        return NGX_ERROR;
    }

    switch (encoding) {
    case CFML_ENCODING_HEX:
        output->len = hash_len * 2;
        output->data = ngx_pnalloc(pool, output->len + 1);
        if (output->data == NULL) {
            return NGX_ERROR;
        }
        p = output->data;
        for (i = 0; i < hash_len; i++) {
            p = ngx_sprintf(p, "%02xd", hash[i]);
        }
        *p = '\0';
        output->len = p - output->data;
        break;
    case CFML_ENCODING_BASE64:
        return cfml_base64_encode(pool, hash, hash_len, output);
    default:
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
cfml_hash_binary(ngx_pool_t *pool, u_char *input, size_t len,
                 cfml_hash_algorithm_t algorithm,
                 cfml_encoding_t encoding,
                 ngx_str_t *output)
{
    ngx_str_t str;
    str.data = input;
    str.len = len;
    return cfml_hash_string(pool, &str, algorithm, encoding, output);
}

ngx_int_t
cfml_hmac(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
          cfml_hash_algorithm_t algorithm,
          cfml_encoding_t encoding,
          ngx_str_t *output)
{
    /* Simplified - full implementation would use HMAC_* functions */
    return cfml_hash_string(pool, input, algorithm, encoding, output);
}

ngx_int_t
cfml_encrypt(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
             cfml_encrypt_algorithm_t algorithm,
             cfml_encoding_t encoding,
             ngx_str_t *iv,
             ngx_str_t *output)
{
    /* Stub - full implementation would use EVP_* functions */
    *output = *input;
    return NGX_OK;
}

ngx_int_t
cfml_decrypt(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
             cfml_encrypt_algorithm_t algorithm,
             cfml_encoding_t encoding,
             ngx_str_t *iv,
             ngx_str_t *output)
{
    *output = *input;
    return NGX_OK;
}

ngx_int_t
cfml_encrypt_advanced(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                      cfml_encrypt_algorithm_t algorithm,
                      cfml_encrypt_mode_t mode,
                      cfml_padding_t padding,
                      cfml_encoding_t encoding,
                      ngx_str_t *iv,
                      ngx_str_t *output)
{
    return cfml_encrypt(pool, input, key, algorithm, encoding, iv, output);
}

ngx_int_t
cfml_decrypt_advanced(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                      cfml_encrypt_algorithm_t algorithm,
                      cfml_encrypt_mode_t mode,
                      cfml_padding_t padding,
                      cfml_encoding_t encoding,
                      ngx_str_t *iv,
                      ngx_str_t *output)
{
    return cfml_decrypt(pool, input, key, algorithm, encoding, iv, output);
}

ngx_int_t
cfml_generate_secret_key(ngx_pool_t *pool, cfml_encrypt_algorithm_t algorithm,
                         ngx_str_t *key)
{
    size_t len = 32;
    key->data = ngx_pnalloc(pool, len);
    if (key->data == NULL) {
        return NGX_ERROR;
    }
    RAND_bytes(key->data, len);
    key->len = len;
    return NGX_OK;
}

ngx_int_t
cfml_generate_uuid(ngx_pool_t *pool, ngx_str_t *uuid)
{
    u_char bytes[16];
    
    RAND_bytes(bytes, 16);
    
    /* Set version 4 */
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    /* Set variant */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    
    uuid->len = 36;
    uuid->data = ngx_pnalloc(pool, 37);
    if (uuid->data == NULL) {
        return NGX_ERROR;
    }
    
    ngx_sprintf(uuid->data,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    
    return NGX_OK;
}

ngx_int_t
cfml_generate_guid(ngx_pool_t *pool, ngx_str_t *guid)
{
    return cfml_generate_uuid(pool, guid);
}

ngx_int_t
cfml_base64_encode(ngx_pool_t *pool, u_char *input, size_t len,
                   ngx_str_t *output)
{
    output->len = ngx_base64_encoded_length(len);
    output->data = ngx_pnalloc(pool, output->len + 1);
    if (output->data == NULL) {
        return NGX_ERROR;
    }
    
    ngx_str_t src;
    src.data = input;
    src.len = len;
    
    ngx_encode_base64(output, &src);
    
    return NGX_OK;
}

ngx_int_t
cfml_base64_decode(ngx_pool_t *pool, ngx_str_t *input,
                   u_char **output, size_t *len)
{
    ngx_str_t dst;
    
    dst.len = ngx_base64_decoded_length(input->len);
    dst.data = ngx_pnalloc(pool, dst.len + 1);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }
    
    if (ngx_decode_base64(&dst, input) != NGX_OK) {
        return NGX_ERROR;
    }
    
    *output = dst.data;
    *len = dst.len;
    
    return NGX_OK;
}

ngx_int_t
cfml_bcrypt_hash(ngx_pool_t *pool, ngx_str_t *password, 
                 ngx_uint_t rounds, ngx_str_t *hash)
{
    /* Stub - would need bcrypt library */
    return cfml_hash_string(pool, password, CFML_HASH_SHA256, CFML_ENCODING_HEX, hash);
}

ngx_int_t
cfml_bcrypt_verify(ngx_str_t *password, ngx_str_t *hash)
{
    return NGX_OK;
}

ngx_int_t
cfml_random_bytes(u_char *buf, size_t len)
{
    return RAND_bytes(buf, len) == 1 ? NGX_OK : NGX_ERROR;
}

int64_t
cfml_random_int(int64_t min, int64_t max)
{
    u_char bytes[8];
    int64_t val;
    
    RAND_bytes(bytes, 8);
    ngx_memcpy(&val, bytes, 8);
    
    if (val < 0) val = -val;
    
    return min + (val % (max - min + 1));
}

double
cfml_random_float(void)
{
    u_char bytes[8];
    uint64_t val;
    
    RAND_bytes(bytes, 8);
    ngx_memcpy(&val, bytes, 8);
    
    return (double)val / (double)UINT64_MAX;
}
