/*
 * CFML Hash - Cryptographic functions
 */

#ifndef _CFML_HASH_H_
#define _CFML_HASH_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Hash algorithms */
typedef enum {
    CFML_HASH_MD5 = 0,
    CFML_HASH_SHA,
    CFML_HASH_SHA1,
    CFML_HASH_SHA256,
    CFML_HASH_SHA384,
    CFML_HASH_SHA512
} cfml_hash_algorithm_t;

/* Encoding types */
typedef enum {
    CFML_ENCODING_HEX = 0,
    CFML_ENCODING_BASE64,
    CFML_ENCODING_UU
} cfml_encoding_t;

/* Hash functions */
ngx_int_t cfml_hash_string(ngx_pool_t *pool, ngx_str_t *input,
                           cfml_hash_algorithm_t algorithm,
                           cfml_encoding_t encoding,
                           ngx_str_t *output);

ngx_int_t cfml_hash_binary(ngx_pool_t *pool, u_char *input, size_t len,
                           cfml_hash_algorithm_t algorithm,
                           cfml_encoding_t encoding,
                           ngx_str_t *output);

/* HMAC functions */
ngx_int_t cfml_hmac(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                    cfml_hash_algorithm_t algorithm,
                    cfml_encoding_t encoding,
                    ngx_str_t *output);

/* Encryption algorithms */
typedef enum {
    CFML_ENCRYPT_AES = 0,
    CFML_ENCRYPT_AES_128,
    CFML_ENCRYPT_AES_192,
    CFML_ENCRYPT_AES_256,
    CFML_ENCRYPT_BLOWFISH,
    CFML_ENCRYPT_DES,
    CFML_ENCRYPT_3DES
} cfml_encrypt_algorithm_t;

/* Encryption modes */
typedef enum {
    CFML_MODE_CBC = 0,
    CFML_MODE_ECB,
    CFML_MODE_CFB,
    CFML_MODE_OFB,
    CFML_MODE_GCM
} cfml_encrypt_mode_t;

/* Padding types */
typedef enum {
    CFML_PADDING_PKCS5 = 0,
    CFML_PADDING_NONE,
    CFML_PADDING_ZERO
} cfml_padding_t;

/* Encryption/Decryption */
ngx_int_t cfml_encrypt(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                       cfml_encrypt_algorithm_t algorithm,
                       cfml_encoding_t encoding,
                       ngx_str_t *iv,
                       ngx_str_t *output);

ngx_int_t cfml_decrypt(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                       cfml_encrypt_algorithm_t algorithm,
                       cfml_encoding_t encoding,
                       ngx_str_t *iv,
                       ngx_str_t *output);

ngx_int_t cfml_encrypt_advanced(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                                cfml_encrypt_algorithm_t algorithm,
                                cfml_encrypt_mode_t mode,
                                cfml_padding_t padding,
                                cfml_encoding_t encoding,
                                ngx_str_t *iv,
                                ngx_str_t *output);

ngx_int_t cfml_decrypt_advanced(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *key,
                                cfml_encrypt_algorithm_t algorithm,
                                cfml_encrypt_mode_t mode,
                                cfml_padding_t padding,
                                cfml_encoding_t encoding,
                                ngx_str_t *iv,
                                ngx_str_t *output);

/* Key generation */
ngx_int_t cfml_generate_secret_key(ngx_pool_t *pool, cfml_encrypt_algorithm_t algorithm,
                                   ngx_str_t *key);

/* UUID/GUID generation */
ngx_int_t cfml_generate_uuid(ngx_pool_t *pool, ngx_str_t *uuid);
ngx_int_t cfml_generate_guid(ngx_pool_t *pool, ngx_str_t *guid);

/* Base64 encoding */
ngx_int_t cfml_base64_encode(ngx_pool_t *pool, u_char *input, size_t len,
                             ngx_str_t *output);
ngx_int_t cfml_base64_decode(ngx_pool_t *pool, ngx_str_t *input,
                             u_char **output, size_t *len);

/* BCrypt for password hashing */
ngx_int_t cfml_bcrypt_hash(ngx_pool_t *pool, ngx_str_t *password, 
                           ngx_uint_t rounds, ngx_str_t *hash);
ngx_int_t cfml_bcrypt_verify(ngx_str_t *password, ngx_str_t *hash);

/* Random number generation */
ngx_int_t cfml_random_bytes(u_char *buf, size_t len);
int64_t cfml_random_int(int64_t min, int64_t max);
double cfml_random_float(void);

#endif /* _CFML_HASH_H_ */
