/*
 * CFML Auth - JWT/OAuth2 support
 * Token validation, JWKS, claims extraction
 */

#ifndef _CFML_AUTH_H_
#define _CFML_AUTH_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* JWT algorithms */
typedef enum {
    CFML_JWT_ALG_NONE = 0,
    CFML_JWT_ALG_HS256,         /* HMAC SHA-256 */
    CFML_JWT_ALG_HS384,         /* HMAC SHA-384 */
    CFML_JWT_ALG_HS512,         /* HMAC SHA-512 */
    CFML_JWT_ALG_RS256,         /* RSA SHA-256 */
    CFML_JWT_ALG_RS384,         /* RSA SHA-384 */
    CFML_JWT_ALG_RS512,         /* RSA SHA-512 */
    CFML_JWT_ALG_ES256,         /* ECDSA P-256 SHA-256 */
    CFML_JWT_ALG_ES384,         /* ECDSA P-384 SHA-384 */
    CFML_JWT_ALG_ES512,         /* ECDSA P-521 SHA-512 */
    CFML_JWT_ALG_PS256,         /* RSA-PSS SHA-256 */
    CFML_JWT_ALG_PS384,         /* RSA-PSS SHA-384 */
    CFML_JWT_ALG_PS512          /* RSA-PSS SHA-512 */
} cfml_jwt_alg_t;

/* JWT header */
typedef struct {
    cfml_jwt_alg_t      alg;
    ngx_str_t           alg_str;
    ngx_str_t           typ;        /* Usually "JWT" */
    ngx_str_t           kid;        /* Key ID */
    ngx_str_t           jku;        /* JWK Set URL */
} cfml_jwt_header_t;

/* JWT standard claims */
typedef struct {
    ngx_str_t           iss;        /* Issuer */
    ngx_str_t           sub;        /* Subject */
    ngx_str_t           aud;        /* Audience (can be array) */
    time_t              exp;        /* Expiration time */
    time_t              nbf;        /* Not before */
    time_t              iat;        /* Issued at */
    ngx_str_t           jti;        /* JWT ID */
} cfml_jwt_claims_t;

/* Parsed JWT */
typedef struct {
    ngx_str_t               raw;            /* Original token */
    ngx_str_t               header_b64;     /* Base64 header */
    ngx_str_t               payload_b64;    /* Base64 payload */
    ngx_str_t               signature_b64;  /* Base64 signature */
    ngx_str_t               header_json;    /* Decoded header JSON */
    ngx_str_t               payload_json;   /* Decoded payload JSON */
    cfml_jwt_header_t       header;         /* Parsed header */
    cfml_jwt_claims_t       claims;         /* Standard claims */
    cfml_struct_t           *payload;       /* Full payload as struct */
    unsigned                valid:1;
    unsigned                expired:1;
    unsigned                not_yet_valid:1;
    ngx_str_t               error;
    ngx_pool_t              *pool;
} cfml_jwt_t;

/* JWK (JSON Web Key) */
typedef struct {
    ngx_str_t           kty;        /* Key type (RSA, EC, oct) */
    ngx_str_t           use;        /* Use (sig, enc) */
    ngx_str_t           alg;        /* Algorithm */
    ngx_str_t           kid;        /* Key ID */
    
    /* RSA key components */
    ngx_str_t           n;          /* Modulus */
    ngx_str_t           e;          /* Exponent */
    
    /* EC key components */
    ngx_str_t           crv;        /* Curve (P-256, P-384, P-521) */
    ngx_str_t           x;          /* X coordinate */
    ngx_str_t           y;          /* Y coordinate */
    
    /* Symmetric key */
    ngx_str_t           k;          /* Key value */
    
    /* OpenSSL key handle */
    void                *pkey;      /* EVP_PKEY* */
    
    ngx_pool_t          *pool;
} cfml_jwk_t;

/* JWKS (JSON Web Key Set) */
typedef struct {
    ngx_array_t         *keys;      /* Array of cfml_jwk_t */
    ngx_msec_t          fetched_at;
    ngx_msec_t          expires_at;
    ngx_str_t           url;
    ngx_pool_t          *pool;
} cfml_jwks_t;

/* JWT validation options */
typedef struct {
    ngx_str_t           secret;         /* For HMAC algorithms */
    cfml_jwk_t          *key;           /* For RSA/EC algorithms */
    cfml_jwks_t         *jwks;          /* Key set */
    ngx_str_t           issuer;         /* Expected issuer */
    ngx_str_t           audience;       /* Expected audience */
    ngx_int_t           clock_skew;     /* Allowed clock skew in seconds */
    unsigned            verify_exp:1;   /* Verify expiration */
    unsigned            verify_nbf:1;   /* Verify not-before */
    unsigned            verify_iat:1;   /* Verify issued-at */
    unsigned            verify_iss:1;   /* Verify issuer */
    unsigned            verify_aud:1;   /* Verify audience */
    unsigned            verify_sig:1;   /* Verify signature */
} cfml_jwt_options_t;

/* OAuth2 token response */
typedef struct {
    ngx_str_t           access_token;
    ngx_str_t           token_type;
    ngx_str_t           refresh_token;
    ngx_str_t           id_token;
    ngx_int_t           expires_in;
    ngx_str_t           scope;
    ngx_str_t           error;
    ngx_str_t           error_description;
} cfml_oauth2_token_t;

/*
 * JWT Functions
 */

/* Parse JWT without validation */
cfml_jwt_t *cfml_jwt_parse(ngx_pool_t *pool, ngx_str_t *token);

/* Validate JWT */
ngx_int_t cfml_jwt_validate(cfml_jwt_t *jwt, cfml_jwt_options_t *options);

/* Decode JWT and validate in one step */
cfml_jwt_t *cfml_jwt_decode(ngx_pool_t *pool, ngx_str_t *token, 
                            cfml_jwt_options_t *options);

/* Get claim from JWT payload */
cfml_value_t *cfml_jwt_get_claim(cfml_jwt_t *jwt, ngx_str_t *name);

/* Create JWT */
ngx_str_t *cfml_jwt_encode(ngx_pool_t *pool, cfml_struct_t *payload,
                           cfml_jwt_options_t *options);

/* Refresh JWT using refresh token */
cfml_jwt_t *cfml_jwt_refresh(ngx_pool_t *pool, ngx_str_t *refresh_token,
                             ngx_str_t *token_endpoint, ngx_str_t *client_id,
                             ngx_str_t *client_secret);

/*
 * JWK/JWKS Functions
 */

/* Parse JWK from JSON */
cfml_jwk_t *cfml_jwk_parse(ngx_pool_t *pool, ngx_str_t *json);

/* Parse JWKS from JSON */
cfml_jwks_t *cfml_jwks_parse(ngx_pool_t *pool, ngx_str_t *json);

/* Fetch JWKS from URL */
cfml_jwks_t *cfml_jwks_fetch(ngx_pool_t *pool, ngx_str_t *url);

/* Find key in JWKS by kid */
cfml_jwk_t *cfml_jwks_get_key(cfml_jwks_t *jwks, ngx_str_t *kid);

/* Convert JWK to OpenSSL EVP_PKEY */
void *cfml_jwk_to_pkey(cfml_jwk_t *jwk);

/*
 * OAuth2 Functions
 */

/* Exchange authorization code for tokens */
cfml_oauth2_token_t *cfml_oauth2_exchange_code(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *code, ngx_str_t *redirect_uri,
    ngx_str_t *client_id, ngx_str_t *client_secret);

/* Refresh access token */
cfml_oauth2_token_t *cfml_oauth2_refresh_token(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *refresh_token,
    ngx_str_t *client_id, ngx_str_t *client_secret);

/* Client credentials grant */
cfml_oauth2_token_t *cfml_oauth2_client_credentials(ngx_pool_t *pool,
    ngx_str_t *token_endpoint, ngx_str_t *client_id, ngx_str_t *client_secret,
    ngx_str_t *scope);

/* Build authorization URL */
ngx_str_t *cfml_oauth2_auth_url(ngx_pool_t *pool, ngx_str_t *auth_endpoint,
    ngx_str_t *client_id, ngx_str_t *redirect_uri, ngx_str_t *scope,
    ngx_str_t *state, ngx_str_t *nonce);

/*
 * Base64URL Functions (JWT uses URL-safe base64)
 */

ngx_str_t *cfml_base64url_encode(ngx_pool_t *pool, ngx_str_t *input);
ngx_str_t *cfml_base64url_decode(ngx_pool_t *pool, ngx_str_t *input);

/*
 * CFML Function Implementations
 */

/* JWTDecode(token [, secret] [, options]) */
cfml_value_t *cfml_func_jwtdecode(cfml_context_t *ctx, ngx_array_t *args);

/* JWTEncode(payload, secret [, algorithm]) */
cfml_value_t *cfml_func_jwtencode(cfml_context_t *ctx, ngx_array_t *args);

/* JWTVerify(token, secret [, options]) */
cfml_value_t *cfml_func_jwtverify(cfml_context_t *ctx, ngx_array_t *args);

/* JWKSFetch(url) */
cfml_value_t *cfml_func_jwksfetch(cfml_context_t *ctx, ngx_array_t *args);

/* OAuth2AuthURL(endpoint, clientId, redirectUri [, scope] [, state]) */
cfml_value_t *cfml_func_oauth2authurl(cfml_context_t *ctx, ngx_array_t *args);

/* OAuth2ExchangeCode(tokenEndpoint, code, redirectUri, clientId, clientSecret) */
cfml_value_t *cfml_func_oauth2exchangecode(cfml_context_t *ctx, ngx_array_t *args);

/* OAuth2RefreshToken(tokenEndpoint, refreshToken, clientId, clientSecret) */
cfml_value_t *cfml_func_oauth2refreshtoken(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_AUTH_H_ */
