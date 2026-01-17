/*
 * CFML Auth - JWT/OAuth2 implementation
 * Uses OpenSSL for cryptographic operations
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "cfml_auth.h"
#include "cfml_json.h"
#include "cfml_http.h"
#include "cfml_variables.h"

/* Algorithm string mapping */
static struct {
    const char *name;
    cfml_jwt_alg_t alg;
} jwt_algorithms[] = {
    { "none",  CFML_JWT_ALG_NONE },
    { "HS256", CFML_JWT_ALG_HS256 },
    { "HS384", CFML_JWT_ALG_HS384 },
    { "HS512", CFML_JWT_ALG_HS512 },
    { "RS256", CFML_JWT_ALG_RS256 },
    { "RS384", CFML_JWT_ALG_RS384 },
    { "RS512", CFML_JWT_ALG_RS512 },
    { "ES256", CFML_JWT_ALG_ES256 },
    { "ES384", CFML_JWT_ALG_ES384 },
    { "ES512", CFML_JWT_ALG_ES512 },
    { "PS256", CFML_JWT_ALG_PS256 },
    { "PS384", CFML_JWT_ALG_PS384 },
    { "PS512", CFML_JWT_ALG_PS512 },
    { NULL, CFML_JWT_ALG_NONE }
};

/* Base64URL character set */
static const u_char base64url_encode_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const u_char base64url_decode_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

/* Base64URL encode */
ngx_str_t *
cfml_base64url_encode(ngx_pool_t *pool, ngx_str_t *input)
{
    ngx_str_t *output;
    size_t len, i;
    u_char *p, *src;
    uint32_t v;
    
    len = (input->len + 2) / 3 * 4;  /* Base64 length */
    
    output = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (output == NULL) {
        return NULL;
    }
    
    output->data = ngx_pnalloc(pool, len + 1);
    if (output->data == NULL) {
        return NULL;
    }
    
    p = output->data;
    src = input->data;
    
    for (i = 0; i + 2 < input->len; i += 3) {
        v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
        *p++ = base64url_encode_table[(v >> 18) & 0x3F];
        *p++ = base64url_encode_table[(v >> 12) & 0x3F];
        *p++ = base64url_encode_table[(v >> 6) & 0x3F];
        *p++ = base64url_encode_table[v & 0x3F];
    }
    
    /* Handle remaining bytes (no padding in base64url) */
    if (i < input->len) {
        v = src[i] << 16;
        if (i + 1 < input->len) {
            v |= src[i + 1] << 8;
        }
        *p++ = base64url_encode_table[(v >> 18) & 0x3F];
        *p++ = base64url_encode_table[(v >> 12) & 0x3F];
        if (i + 1 < input->len) {
            *p++ = base64url_encode_table[(v >> 6) & 0x3F];
        }
    }
    
    *p = '\0';
    output->len = p - output->data;
    
    return output;
}

/* Base64URL decode */
ngx_str_t *
cfml_base64url_decode(ngx_pool_t *pool, ngx_str_t *input)
{
    ngx_str_t *output;
    size_t len, i;
    u_char *p, *src;
    uint32_t v;
    u_char c;
    
    /* Calculate output length */
    len = input->len * 3 / 4;
    
    output = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (output == NULL) {
        return NULL;
    }
    
    output->data = ngx_pnalloc(pool, len + 1);
    if (output->data == NULL) {
        return NULL;
    }
    
    p = output->data;
    src = input->data;
    v = 0;
    
    for (i = 0; i < input->len; i++) {
        c = base64url_decode_table[src[i]];
        if (c == 64) {
            continue;  /* Skip invalid characters */
        }
        
        v = (v << 6) | c;
        
        if ((i + 1) % 4 == 0) {
            *p++ = (v >> 16) & 0xFF;
            *p++ = (v >> 8) & 0xFF;
            *p++ = v & 0xFF;
            v = 0;
        }
    }
    
    /* Handle remaining bits */
    switch (input->len % 4) {
    case 2:
        v <<= 12;
        *p++ = (v >> 16) & 0xFF;
        break;
    case 3:
        v <<= 6;
        *p++ = (v >> 16) & 0xFF;
        *p++ = (v >> 8) & 0xFF;
        break;
    }
    
    *p = '\0';
    output->len = p - output->data;
    
    return output;
}

/* Parse algorithm string to enum */
static cfml_jwt_alg_t
parse_algorithm(ngx_str_t *alg)
{
    int i;
    
    for (i = 0; jwt_algorithms[i].name != NULL; i++) {
        if (ngx_strncmp(alg->data, jwt_algorithms[i].name, alg->len) == 0) {
            return jwt_algorithms[i].alg;
        }
    }
    
    return CFML_JWT_ALG_NONE;
}

/* Get algorithm string from enum */
static const char *
algorithm_to_string(cfml_jwt_alg_t alg)
{
    int i;
    
    for (i = 0; jwt_algorithms[i].name != NULL; i++) {
        if (jwt_algorithms[i].alg == alg) {
            return jwt_algorithms[i].name;
        }
    }
    
    return "none";
}

/* Parse JWT header */
static ngx_int_t
parse_jwt_header(cfml_jwt_t *jwt, ngx_str_t *json)
{
    cfml_value_t *header_val;
    cfml_value_t *val;
    ngx_str_t key;
    
    header_val = cfml_json_parse(jwt->pool, json);
    if (header_val == NULL || header_val->type != CFML_TYPE_STRUCT) {
        jwt->error.data = (u_char *)"Invalid JWT header";
        jwt->error.len = 18;
        return NGX_ERROR;
    }
    
    /* Get algorithm */
    ngx_str_set(&key, "alg");
    val = cfml_struct_get(header_val->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->header.alg_str = val->data.string;
        jwt->header.alg = parse_algorithm(&val->data.string);
    }
    
    /* Get type */
    ngx_str_set(&key, "typ");
    val = cfml_struct_get(header_val->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->header.typ = val->data.string;
    }
    
    /* Get key ID */
    ngx_str_set(&key, "kid");
    val = cfml_struct_get(header_val->data.structure, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->header.kid = val->data.string;
    }
    
    return NGX_OK;
}

/* Parse JWT claims */
static ngx_int_t
parse_jwt_claims(cfml_jwt_t *jwt, ngx_str_t *json)
{
    cfml_value_t *payload_val;
    cfml_value_t *val;
    ngx_str_t key;
    
    payload_val = cfml_json_parse(jwt->pool, json);
    if (payload_val == NULL || payload_val->type != CFML_TYPE_STRUCT) {
        jwt->error.data = (u_char *)"Invalid JWT payload";
        jwt->error.len = 19;
        return NGX_ERROR;
    }
    
    jwt->payload = payload_val->data.structure;
    
    /* Extract standard claims */
    ngx_str_set(&key, "iss");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->claims.iss = val->data.string;
    }
    
    ngx_str_set(&key, "sub");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->claims.sub = val->data.string;
    }
    
    ngx_str_set(&key, "aud");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->claims.aud = val->data.string;
    }
    
    ngx_str_set(&key, "exp");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_INTEGER) {
        jwt->claims.exp = val->data.integer;
    }
    
    ngx_str_set(&key, "nbf");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_INTEGER) {
        jwt->claims.nbf = val->data.integer;
    }
    
    ngx_str_set(&key, "iat");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_INTEGER) {
        jwt->claims.iat = val->data.integer;
    }
    
    ngx_str_set(&key, "jti");
    val = cfml_struct_get(jwt->payload, &key);
    if (val && val->type == CFML_TYPE_STRING) {
        jwt->claims.jti = val->data.string;
    }
    
    return NGX_OK;
}

/* Parse JWT without validation */
cfml_jwt_t *
cfml_jwt_parse(ngx_pool_t *pool, ngx_str_t *token)
{
    cfml_jwt_t *jwt;
    u_char *p, *end, *dot1, *dot2;
    ngx_str_t *decoded;
    
    jwt = ngx_pcalloc(pool, sizeof(cfml_jwt_t));
    if (jwt == NULL) {
        return NULL;
    }
    
    jwt->pool = pool;
    jwt->raw = *token;
    
    /* Find the two dots separating header.payload.signature */
    p = token->data;
    end = token->data + token->len;
    
    dot1 = ngx_strlchr(p, end, '.');
    if (dot1 == NULL) {
        jwt->error.data = (u_char *)"Invalid JWT format - missing first dot";
        jwt->error.len = 38;
        return jwt;
    }
    
    dot2 = ngx_strlchr(dot1 + 1, end, '.');
    if (dot2 == NULL) {
        jwt->error.data = (u_char *)"Invalid JWT format - missing second dot";
        jwt->error.len = 39;
        return jwt;
    }
    
    /* Split into parts */
    jwt->header_b64.data = p;
    jwt->header_b64.len = dot1 - p;
    
    jwt->payload_b64.data = dot1 + 1;
    jwt->payload_b64.len = dot2 - dot1 - 1;
    
    jwt->signature_b64.data = dot2 + 1;
    jwt->signature_b64.len = end - dot2 - 1;
    
    /* Decode header */
    decoded = cfml_base64url_decode(pool, &jwt->header_b64);
    if (decoded == NULL) {
        jwt->error.data = (u_char *)"Failed to decode JWT header";
        jwt->error.len = 27;
        return jwt;
    }
    jwt->header_json = *decoded;
    
    /* Decode payload */
    decoded = cfml_base64url_decode(pool, &jwt->payload_b64);
    if (decoded == NULL) {
        jwt->error.data = (u_char *)"Failed to decode JWT payload";
        jwt->error.len = 28;
        return jwt;
    }
    jwt->payload_json = *decoded;
    
    /* Parse header */
    if (parse_jwt_header(jwt, &jwt->header_json) != NGX_OK) {
        return jwt;
    }
    
    /* Parse claims */
    if (parse_jwt_claims(jwt, &jwt->payload_json) != NGX_OK) {
        return jwt;
    }
    
    jwt->valid = 1;
    
    return jwt;
}

/* Verify HMAC signature */
static ngx_int_t
verify_hmac_signature(cfml_jwt_t *jwt, ngx_str_t *secret, const EVP_MD *md)
{
    u_char sig[EVP_MAX_MD_SIZE];
    unsigned int sig_len;
    ngx_str_t signing_input;
    ngx_str_t *expected_sig;
    
    /* Signing input is header.payload */
    signing_input.data = jwt->raw.data;
    signing_input.len = jwt->header_b64.len + 1 + jwt->payload_b64.len;
    
    /* Compute HMAC */
    if (HMAC(md, secret->data, secret->len, 
             signing_input.data, signing_input.len, 
             sig, &sig_len) == NULL) {
        jwt->error.data = (u_char *)"HMAC computation failed";
        jwt->error.len = 23;
        return NGX_ERROR;
    }
    
    /* Base64URL encode computed signature */
    ngx_str_t sig_str = { sig_len, sig };
    expected_sig = cfml_base64url_encode(jwt->pool, &sig_str);
    if (expected_sig == NULL) {
        return NGX_ERROR;
    }
    
    /* Compare */
    if (jwt->signature_b64.len != expected_sig->len ||
        ngx_memcmp(jwt->signature_b64.data, expected_sig->data, 
                   expected_sig->len) != 0) {
        jwt->error.data = (u_char *)"Signature verification failed";
        jwt->error.len = 29;
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

/* Validate JWT */
ngx_int_t
cfml_jwt_validate(cfml_jwt_t *jwt, cfml_jwt_options_t *options)
{
    time_t now;
    const EVP_MD *md = NULL;
    
    if (jwt == NULL || !jwt->valid) {
        return NGX_ERROR;
    }
    
    now = ngx_time();
    
    /* Check expiration */
    if (options->verify_exp && jwt->claims.exp > 0) {
        if (now > jwt->claims.exp + options->clock_skew) {
            jwt->expired = 1;
            jwt->error.data = (u_char *)"Token has expired";
            jwt->error.len = 17;
            return NGX_ERROR;
        }
    }
    
    /* Check not-before */
    if (options->verify_nbf && jwt->claims.nbf > 0) {
        if (now < jwt->claims.nbf - options->clock_skew) {
            jwt->not_yet_valid = 1;
            jwt->error.data = (u_char *)"Token is not yet valid";
            jwt->error.len = 22;
            return NGX_ERROR;
        }
    }
    
    /* Check issuer */
    if (options->verify_iss && options->issuer.len > 0) {
        if (jwt->claims.iss.len != options->issuer.len ||
            ngx_strncmp(jwt->claims.iss.data, options->issuer.data, 
                        options->issuer.len) != 0) {
            jwt->error.data = (u_char *)"Invalid issuer";
            jwt->error.len = 14;
            return NGX_ERROR;
        }
    }
    
    /* Check audience */
    if (options->verify_aud && options->audience.len > 0) {
        if (jwt->claims.aud.len != options->audience.len ||
            ngx_strncmp(jwt->claims.aud.data, options->audience.data,
                        options->audience.len) != 0) {
            jwt->error.data = (u_char *)"Invalid audience";
            jwt->error.len = 16;
            return NGX_ERROR;
        }
    }
    
    /* Verify signature */
    if (options->verify_sig && options->secret.len > 0) {
        switch (jwt->header.alg) {
        case CFML_JWT_ALG_HS256:
            md = EVP_sha256();
            break;
        case CFML_JWT_ALG_HS384:
            md = EVP_sha384();
            break;
        case CFML_JWT_ALG_HS512:
            md = EVP_sha512();
            break;
        default:
            jwt->error.data = (u_char *)"Unsupported algorithm for HMAC";
            jwt->error.len = 30;
            return NGX_ERROR;
        }
        
        if (verify_hmac_signature(jwt, &options->secret, md) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    /* RSA/EC signature verification would go here */
    /* For now, only HMAC is fully implemented */
    
    return NGX_OK;
}

/* Decode and validate JWT */
cfml_jwt_t *
cfml_jwt_decode(ngx_pool_t *pool, ngx_str_t *token, cfml_jwt_options_t *options)
{
    cfml_jwt_t *jwt;
    
    jwt = cfml_jwt_parse(pool, token);
    if (jwt == NULL || !jwt->valid) {
        return jwt;
    }
    
    if (options) {
        if (cfml_jwt_validate(jwt, options) != NGX_OK) {
            jwt->valid = 0;
        }
    }
    
    return jwt;
}

/* Get claim from JWT */
cfml_value_t *
cfml_jwt_get_claim(cfml_jwt_t *jwt, ngx_str_t *name)
{
    if (jwt == NULL || jwt->payload == NULL) {
        return NULL;
    }
    
    return cfml_struct_get(jwt->payload, name);
}

/* Create JWT */
ngx_str_t *
cfml_jwt_encode(ngx_pool_t *pool, cfml_struct_t *payload, cfml_jwt_options_t *options)
{
    ngx_str_t *result;
    ngx_str_t *header_json;
    ngx_str_t *payload_json;
    ngx_str_t *header_b64;
    ngx_str_t *payload_b64;
    ngx_str_t signing_input;
    u_char sig[EVP_MAX_MD_SIZE];
    unsigned int sig_len;
    ngx_str_t *sig_b64;
    const EVP_MD *md = NULL;
    cfml_jwt_alg_t alg = CFML_JWT_ALG_HS256;
    cfml_value_t *payload_val;
    u_char *p;
    
    if (options == NULL || options->secret.len == 0) {
        return NULL;
    }
    
    /* Build header */
    header_json = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (header_json == NULL) {
        return NULL;
    }
    
    header_json->data = ngx_pnalloc(pool, 64);
    if (header_json->data == NULL) {
        return NULL;
    }
    
    header_json->len = ngx_sprintf(header_json->data, 
        "{\"alg\":\"%s\",\"typ\":\"JWT\"}", algorithm_to_string(alg)) 
        - header_json->data;
    
    /* Serialize payload */
    payload_val = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (payload_val == NULL) {
        return NULL;
    }
    payload_val->type = CFML_TYPE_STRUCT;
    payload_val->data.structure = payload;
    
    payload_json = cfml_json_serialize(pool, payload_val);
    if (payload_json == NULL) {
        return NULL;
    }
    
    /* Base64URL encode */
    header_b64 = cfml_base64url_encode(pool, header_json);
    payload_b64 = cfml_base64url_encode(pool, payload_json);
    
    if (header_b64 == NULL || payload_b64 == NULL) {
        return NULL;
    }
    
    /* Create signing input */
    signing_input.len = header_b64->len + 1 + payload_b64->len;
    signing_input.data = ngx_pnalloc(pool, signing_input.len);
    if (signing_input.data == NULL) {
        return NULL;
    }
    
    p = signing_input.data;
    p = ngx_copy(p, header_b64->data, header_b64->len);
    *p++ = '.';
    p = ngx_copy(p, payload_b64->data, payload_b64->len);
    
    /* Compute signature */
    switch (alg) {
    case CFML_JWT_ALG_HS256:
        md = EVP_sha256();
        break;
    case CFML_JWT_ALG_HS384:
        md = EVP_sha384();
        break;
    case CFML_JWT_ALG_HS512:
        md = EVP_sha512();
        break;
    default:
        return NULL;
    }
    
    if (HMAC(md, options->secret.data, options->secret.len,
             signing_input.data, signing_input.len,
             sig, &sig_len) == NULL) {
        return NULL;
    }
    
    /* Base64URL encode signature */
    ngx_str_t sig_str = { sig_len, sig };
    sig_b64 = cfml_base64url_encode(pool, &sig_str);
    if (sig_b64 == NULL) {
        return NULL;
    }
    
    /* Build final token */
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->len = signing_input.len + 1 + sig_b64->len;
    result->data = ngx_pnalloc(pool, result->len + 1);
    if (result->data == NULL) {
        return NULL;
    }
    
    p = result->data;
    p = ngx_copy(p, signing_input.data, signing_input.len);
    *p++ = '.';
    p = ngx_copy(p, sig_b64->data, sig_b64->len);
    *p = '\0';
    
    return result;
}

/* Parse JWK from JSON */
cfml_jwk_t *
cfml_jwk_parse(ngx_pool_t *pool, ngx_str_t *json)
{
    cfml_jwk_t *jwk;
    cfml_value_t *val;
    cfml_value_t *prop;
    ngx_str_t key;
    
    val = cfml_json_parse(pool, json);
    if (val == NULL || val->type != CFML_TYPE_STRUCT) {
        return NULL;
    }
    
    jwk = ngx_pcalloc(pool, sizeof(cfml_jwk_t));
    if (jwk == NULL) {
        return NULL;
    }
    
    jwk->pool = pool;
    
    /* Parse key type */
    ngx_str_set(&key, "kty");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->kty = prop->data.string;
    }
    
    /* Parse key ID */
    ngx_str_set(&key, "kid");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->kid = prop->data.string;
    }
    
    /* Parse use */
    ngx_str_set(&key, "use");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->use = prop->data.string;
    }
    
    /* Parse algorithm */
    ngx_str_set(&key, "alg");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->alg = prop->data.string;
    }
    
    /* RSA key components */
    ngx_str_set(&key, "n");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->n = prop->data.string;
    }
    
    ngx_str_set(&key, "e");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->e = prop->data.string;
    }
    
    /* EC key components */
    ngx_str_set(&key, "crv");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->crv = prop->data.string;
    }
    
    ngx_str_set(&key, "x");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->x = prop->data.string;
    }
    
    ngx_str_set(&key, "y");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->y = prop->data.string;
    }
    
    /* Symmetric key */
    ngx_str_set(&key, "k");
    prop = cfml_struct_get(val->data.structure, &key);
    if (prop && prop->type == CFML_TYPE_STRING) {
        jwk->k = prop->data.string;
    }
    
    return jwk;
}

/* Parse JWKS from JSON */
cfml_jwks_t *
cfml_jwks_parse(ngx_pool_t *pool, ngx_str_t *json)
{
    cfml_jwks_t *jwks;
    cfml_value_t *val;
    cfml_value_t *keys_val;
    cfml_value_t **keys;
    ngx_str_t key;
    ngx_uint_t i;
    
    val = cfml_json_parse(pool, json);
    if (val == NULL || val->type != CFML_TYPE_STRUCT) {
        return NULL;
    }
    
    jwks = ngx_pcalloc(pool, sizeof(cfml_jwks_t));
    if (jwks == NULL) {
        return NULL;
    }
    
    jwks->pool = pool;
    jwks->fetched_at = ngx_current_msec;
    
    /* Get keys array */
    ngx_str_set(&key, "keys");
    keys_val = cfml_struct_get(val->data.structure, &key);
    if (keys_val == NULL || keys_val->type != CFML_TYPE_ARRAY) {
        return NULL;
    }
    
    jwks->keys = ngx_array_create(pool, keys_val->data.array->items->nelts,
                                  sizeof(cfml_jwk_t));
    if (jwks->keys == NULL) {
        return NULL;
    }
    
    keys = keys_val->data.array->items->elts;
    for (i = 0; i < keys_val->data.array->items->nelts; i++) {
        if (keys[i]->type == CFML_TYPE_STRUCT) {
            ngx_str_t *key_json = cfml_json_serialize(pool, keys[i]);
            if (key_json) {
                cfml_jwk_t *jwk = cfml_jwk_parse(pool, key_json);
                if (jwk) {
                    cfml_jwk_t *entry = ngx_array_push(jwks->keys);
                    if (entry) {
                        *entry = *jwk;
                    }
                }
            }
        }
    }
    
    return jwks;
}

/* Fetch JWKS from URL */
cfml_jwks_t *
cfml_jwks_fetch(ngx_pool_t *pool, ngx_str_t *url)
{
    cfml_http_response_t *resp;
    cfml_jwks_t *jwks;
    
    resp = cfml_http_get(pool, url);
    if (resp == NULL || !resp->succeeded || resp->content.len == 0) {
        return NULL;
    }
    
    jwks = cfml_jwks_parse(pool, &resp->content);
    if (jwks) {
        jwks->url = *url;
    }
    
    return jwks;
}

/* Find key in JWKS by kid */
cfml_jwk_t *
cfml_jwks_get_key(cfml_jwks_t *jwks, ngx_str_t *kid)
{
    cfml_jwk_t *keys;
    ngx_uint_t i;
    
    if (jwks == NULL || jwks->keys == NULL) {
        return NULL;
    }
    
    keys = jwks->keys->elts;
    for (i = 0; i < jwks->keys->nelts; i++) {
        if (keys[i].kid.len == kid->len &&
            ngx_strncmp(keys[i].kid.data, kid->data, kid->len) == 0) {
            return &keys[i];
        }
    }
    
    return NULL;
}

/* OAuth2 authorization URL */
ngx_str_t *
cfml_oauth2_auth_url(ngx_pool_t *pool, ngx_str_t *auth_endpoint,
    ngx_str_t *client_id, ngx_str_t *redirect_uri, ngx_str_t *scope,
    ngx_str_t *state, ngx_str_t *nonce)
{
    ngx_str_t *url;
    ngx_str_t *encoded_redirect;
    ngx_str_t *encoded_scope = NULL;
    u_char *p;
    size_t len;
    
    encoded_redirect = cfml_url_encode(pool, redirect_uri);
    if (encoded_redirect == NULL) {
        return NULL;
    }
    
    if (scope && scope->len > 0) {
        encoded_scope = cfml_url_encode(pool, scope);
    }
    
    /* Calculate length */
    len = auth_endpoint->len + 1;  /* ? */
    len += sizeof("response_type=code&") - 1;
    len += sizeof("client_id=") - 1 + client_id->len;
    len += sizeof("&redirect_uri=") - 1 + encoded_redirect->len;
    
    if (encoded_scope) {
        len += sizeof("&scope=") - 1 + encoded_scope->len;
    }
    if (state && state->len > 0) {
        len += sizeof("&state=") - 1 + state->len;
    }
    if (nonce && nonce->len > 0) {
        len += sizeof("&nonce=") - 1 + nonce->len;
    }
    
    url = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (url == NULL) {
        return NULL;
    }
    
    url->data = ngx_pnalloc(pool, len + 1);
    if (url->data == NULL) {
        return NULL;
    }
    
    p = url->data;
    p = ngx_copy(p, auth_endpoint->data, auth_endpoint->len);
    *p++ = '?';
    p = ngx_sprintf(p, "response_type=code&client_id=%V&redirect_uri=%V",
                    client_id, encoded_redirect);
    
    if (encoded_scope) {
        p = ngx_sprintf(p, "&scope=%V", encoded_scope);
    }
    if (state && state->len > 0) {
        p = ngx_sprintf(p, "&state=%V", state);
    }
    if (nonce && nonce->len > 0) {
        p = ngx_sprintf(p, "&nonce=%V", nonce);
    }
    
    url->len = p - url->data;
    
    return url;
}

/*
 * CFML Function Implementations
 */

cfml_value_t *
cfml_func_jwtdecode(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_jwt_t *jwt;
    cfml_jwt_options_t options;
    cfml_value_t *result;
    ngx_str_t key;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    ngx_memzero(&options, sizeof(options));
    options.verify_exp = 1;
    options.verify_nbf = 1;
    options.clock_skew = 60;  /* 1 minute */
    
    /* Optional secret for HMAC verification */
    if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRING) {
        options.secret = argv[1]->data.string;
        options.verify_sig = 1;
    }
    
    jwt = cfml_jwt_decode(ctx->pool, &argv[0]->data.string, &options);
    
    if (jwt == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* Build result struct */
    result = cfml_create_struct(ctx->pool);
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    ngx_str_set(&key, "valid");
    cfml_struct_set(result->data.structure, &key, 
                    cfml_create_boolean(ctx->pool, jwt->valid && !jwt->expired));
    
    ngx_str_set(&key, "expired");
    cfml_struct_set(result->data.structure, &key,
                    cfml_create_boolean(ctx->pool, jwt->expired));
    
    ngx_str_set(&key, "error");
    cfml_struct_set(result->data.structure, &key,
                    cfml_create_string(ctx->pool, &jwt->error));
    
    ngx_str_set(&key, "header");
    {
        cfml_value_t *header = cfml_create_struct(ctx->pool);
        ngx_str_set(&key, "alg");
        cfml_struct_set(header->data.structure, &key,
                        cfml_create_string(ctx->pool, &jwt->header.alg_str));
        ngx_str_set(&key, "typ");
        cfml_struct_set(header->data.structure, &key,
                        cfml_create_string(ctx->pool, &jwt->header.typ));
        ngx_str_set(&key, "kid");
        cfml_struct_set(header->data.structure, &key,
                        cfml_create_string(ctx->pool, &jwt->header.kid));
        
        ngx_str_set(&key, "header");
        cfml_struct_set(result->data.structure, &key, header);
    }
    
    ngx_str_set(&key, "payload");
    if (jwt->payload) {
        cfml_value_t *payload = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
        if (payload) {
            payload->type = CFML_TYPE_STRUCT;
            payload->data.structure = jwt->payload;
            cfml_struct_set(result->data.structure, &key, payload);
        }
    }
    
    /* Standard claims as convenience properties */
    ngx_str_set(&key, "sub");
    cfml_struct_set(result->data.structure, &key,
                    cfml_create_string(ctx->pool, &jwt->claims.sub));
    
    ngx_str_set(&key, "iss");
    cfml_struct_set(result->data.structure, &key,
                    cfml_create_string(ctx->pool, &jwt->claims.iss));
    
    ngx_str_set(&key, "exp");
    cfml_struct_set(result->data.structure, &key,
                    cfml_create_integer(ctx->pool, jwt->claims.exp));
    
    return result;
}

cfml_value_t *
cfml_func_jwtencode(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_jwt_options_t options;
    ngx_str_t *token;
    
    if (args == NULL || args->nelts < 2) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRUCT || argv[1]->type != CFML_TYPE_STRING) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    ngx_memzero(&options, sizeof(options));
    options.secret = argv[1]->data.string;
    
    token = cfml_jwt_encode(ctx->pool, argv[0]->data.structure, &options);
    
    if (token == NULL) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    return cfml_create_string(ctx->pool, token);
}

cfml_value_t *
cfml_func_jwtverify(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_jwt_t *jwt;
    cfml_jwt_options_t options;
    
    if (args == NULL || args->nelts < 2) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING || argv[1]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    ngx_memzero(&options, sizeof(options));
    options.secret = argv[1]->data.string;
    options.verify_exp = 1;
    options.verify_nbf = 1;
    options.verify_sig = 1;
    options.clock_skew = 60;
    
    jwt = cfml_jwt_decode(ctx->pool, &argv[0]->data.string, &options);
    
    return cfml_create_boolean(ctx->pool, jwt != NULL && jwt->valid && !jwt->expired);
}

cfml_value_t *
cfml_func_jwksfetch(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    cfml_jwks_t *jwks;
    cfml_value_t *result;
    cfml_jwk_t *keys;
    ngx_uint_t i;
    ngx_str_t key;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    jwks = cfml_jwks_fetch(ctx->pool, &argv[0]->data.string);
    
    if (jwks == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* Build result struct */
    result = cfml_create_struct(ctx->pool);
    if (result == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    /* Add keys array */
    ngx_str_set(&key, "keys");
    {
        cfml_value_t *keys_arr = cfml_create_array(ctx->pool);
        if (keys_arr && jwks->keys) {
            keys = jwks->keys->elts;
            for (i = 0; i < jwks->keys->nelts; i++) {
                cfml_value_t *key_struct = cfml_create_struct(ctx->pool);
                if (key_struct) {
                    ngx_str_t prop;
                    
                    ngx_str_set(&prop, "kty");
                    cfml_struct_set(key_struct->data.structure, &prop,
                                    cfml_create_string(ctx->pool, &keys[i].kty));
                    
                    ngx_str_set(&prop, "kid");
                    cfml_struct_set(key_struct->data.structure, &prop,
                                    cfml_create_string(ctx->pool, &keys[i].kid));
                    
                    ngx_str_set(&prop, "alg");
                    cfml_struct_set(key_struct->data.structure, &prop,
                                    cfml_create_string(ctx->pool, &keys[i].alg));
                    
                    cfml_array_append(keys_arr->data.array, key_struct);
                }
            }
        }
        cfml_struct_set(result->data.structure, &key, keys_arr);
    }
    
    return result;
}

cfml_value_t *
cfml_func_oauth2authurl(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *url;
    ngx_str_t empty = ngx_null_string;
    
    if (args == NULL || args->nelts < 3) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    argv = args->elts;
    
    url = cfml_oauth2_auth_url(ctx->pool,
        argv[0]->type == CFML_TYPE_STRING ? &argv[0]->data.string : &empty,
        argv[1]->type == CFML_TYPE_STRING ? &argv[1]->data.string : &empty,
        argv[2]->type == CFML_TYPE_STRING ? &argv[2]->data.string : &empty,
        args->nelts > 3 && argv[3]->type == CFML_TYPE_STRING ? &argv[3]->data.string : NULL,
        args->nelts > 4 && argv[4]->type == CFML_TYPE_STRING ? &argv[4]->data.string : NULL,
        NULL);
    
    if (url == NULL) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    return cfml_create_string(ctx->pool, url);
}

cfml_value_t *
cfml_func_oauth2exchangecode(cfml_context_t *ctx, ngx_array_t *args)
{
    /* Stub - full implementation would use HTTP client */
    (void)args;
    return cfml_create_struct(ctx->pool);
}

cfml_value_t *
cfml_func_oauth2refreshtoken(cfml_context_t *ctx, ngx_array_t *args)
{
    /* Stub - full implementation would use HTTP client */
    (void)args;
    return cfml_create_struct(ctx->pool);
}

/* Stub implementations for JWK to EVP_PKEY conversion */
void *
cfml_jwk_to_pkey(cfml_jwk_t *jwk)
{
    /* TODO: Implement RSA/EC key conversion */
    (void)jwk;
    return NULL;
}

cfml_jwt_t *
cfml_jwt_refresh(ngx_pool_t *pool, ngx_str_t *refresh_token,
                 ngx_str_t *token_endpoint, ngx_str_t *client_id,
                 ngx_str_t *client_secret)
{
    /* TODO: Implement token refresh */
    (void)pool;
    (void)refresh_token;
    (void)token_endpoint;
    (void)client_id;
    (void)client_secret;
    return NULL;
}

cfml_oauth2_token_t *
cfml_oauth2_exchange_code(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *code, ngx_str_t *redirect_uri,
    ngx_str_t *client_id, ngx_str_t *client_secret)
{
    /* TODO: Implement code exchange */
    (void)pool;
    (void)token_endpoint;
    (void)code;
    (void)redirect_uri;
    (void)client_id;
    (void)client_secret;
    return NULL;
}

cfml_oauth2_token_t *
cfml_oauth2_refresh_token(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *refresh_token,
    ngx_str_t *client_id, ngx_str_t *client_secret)
{
    /* TODO: Implement token refresh */
    (void)pool;
    (void)token_endpoint;
    (void)refresh_token;
    (void)client_id;
    (void)client_secret;
    return NULL;
}

cfml_oauth2_token_t *
cfml_oauth2_client_credentials(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *client_id, ngx_str_t *client_secret,
    ngx_str_t *scope)
{
    /* TODO: Implement client credentials grant */
    (void)pool;
    (void)token_endpoint;
    (void)client_id;
    (void)client_secret;
    (void)scope;
    return NULL;
}
