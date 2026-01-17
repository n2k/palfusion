/*
 * CFML S3 - S3-compatible storage client implementation
 * Full AWS Signature V4 implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <time.h>
#include "cfml_s3.h"
#include "cfml_http.h"
#include "cfml_json.h"
#include "cfml_variables.h"

/* Global S3 config */
static cfml_s3_config_t *s3_default_config = NULL;

/* AWS signing constants */
#define AWS_ALGORITHM "AWS4-HMAC-SHA256"
#define AWS_REQUEST   "aws4_request"

/* ============= AWS Signature V4 Implementation ============= */

/* SHA256 hash of data, returns hex-encoded string */
static ngx_str_t *
sha256_hex(ngx_pool_t *pool, u_char *data, size_t len)
{
    ngx_str_t *result;
    u_char hash[SHA256_DIGEST_LENGTH];
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    SHA256(data, len, hash);
    
    result->data = ngx_pnalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
    if (result->data == NULL) {
        return NULL;
    }
    
    ngx_hex_dump(result->data, hash, SHA256_DIGEST_LENGTH);
    result->len = SHA256_DIGEST_LENGTH * 2;
    
    /* Lowercase the hex string */
    ngx_strlow(result->data, result->data, result->len);
    result->data[result->len] = '\0';
    
    return result;
}

/* HMAC-SHA256 - returns raw bytes */
static u_char *
hmac_sha256_raw(ngx_pool_t *pool, u_char *key, size_t key_len,
    u_char *data, size_t data_len, unsigned int *out_len)
{
    u_char *result;
    
    result = ngx_pnalloc(pool, EVP_MAX_MD_SIZE);
    if (result == NULL) {
        return NULL;
    }
    
    HMAC(EVP_sha256(), key, key_len, data, data_len, result, out_len);
    return result;
}

/* Get signing key: AWS4 + secret -> date -> region -> service -> aws4_request */
static u_char *
get_signing_key(ngx_pool_t *pool, ngx_str_t *secret, ngx_str_t *date,
    ngx_str_t *region, unsigned int *key_len)
{
    u_char *k_date, *k_region, *k_service, *k_signing;
    u_char k_secret[256];
    unsigned int len;
    ngx_str_t service = ngx_string("s3");
    ngx_str_t request = ngx_string(AWS_REQUEST);
    
    /* AWS4 + SecretAccessKey */
    ngx_snprintf(k_secret, sizeof(k_secret), "AWS4%V%Z", secret);
    
    /* HMAC(key, date) */
    k_date = hmac_sha256_raw(pool, k_secret, ngx_strlen(k_secret),
                              date->data, date->len, &len);
    if (k_date == NULL) return NULL;
    
    /* HMAC(k_date, region) */
    k_region = hmac_sha256_raw(pool, k_date, len,
                                region->data, region->len, &len);
    if (k_region == NULL) return NULL;
    
    /* HMAC(k_region, "s3") */
    k_service = hmac_sha256_raw(pool, k_region, len,
                                 service.data, service.len, &len);
    if (k_service == NULL) return NULL;
    
    /* HMAC(k_service, "aws4_request") */
    k_signing = hmac_sha256_raw(pool, k_service, len,
                                 request.data, request.len, key_len);
    
    return k_signing;
}

/* URI encode per RFC 3986 */
static ngx_str_t *
uri_encode(ngx_pool_t *pool, ngx_str_t *str, ngx_int_t encode_slash)
{
    ngx_str_t *result;
    u_char *p, *src;
    size_t i, len;
    static u_char hex[] = "0123456789ABCDEF";
    
    /* Calculate encoded length */
    len = 0;
    for (i = 0; i < str->len; i++) {
        u_char c = str->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' ||
            c == '~' || c == '.' || (c == '/' && !encode_slash)) {
            len++;
        } else {
            len += 3;
        }
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) return NULL;
    
    result->data = ngx_pnalloc(pool, len + 1);
    if (result->data == NULL) return NULL;
    
    p = result->data;
    src = str->data;
    
    for (i = 0; i < str->len; i++) {
        u_char c = src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' ||
            c == '~' || c == '.' || (c == '/' && !encode_slash)) {
            *p++ = c;
        } else {
            *p++ = '%';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 0xf];
        }
    }
    
    result->len = p - result->data;
    result->data[result->len] = '\0';
    return result;
}

/* Format timestamp */
static void
format_timestamp(u_char *amz_date, u_char *date_stamp, time_t t)
{
    struct tm *tm;
    
    tm = gmtime(&t);
    
    /* amz_date: YYYYMMDD'T'HHMMSS'Z' */
    ngx_sprintf(amz_date, "%04d%02d%02dT%02d%02d%02dZ%Z",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    /* date_stamp: YYYYMMDD */
    ngx_sprintf(date_stamp, "%04d%02d%02d%Z",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
}

/* Build canonical request */
static ngx_str_t *
build_canonical_request(ngx_pool_t *pool, const char *method, ngx_str_t *uri,
    ngx_str_t *query, ngx_str_t *headers, ngx_str_t *signed_headers,
    ngx_str_t *payload_hash)
{
    ngx_str_t *result;
    ngx_str_t *encoded_uri;
    size_t len;
    
    encoded_uri = uri_encode(pool, uri, 0);
    if (encoded_uri == NULL) return NULL;
    
    /* Calculate total length */
    len = ngx_strlen(method) + 1 +      /* METHOD\n */
          encoded_uri->len + 1 +         /* URI\n */
          (query ? query->len : 0) + 1 + /* QUERY\n */
          headers->len + 1 +             /* HEADERS\n */
          signed_headers->len + 1 +      /* SIGNED_HEADERS\n */
          payload_hash->len;             /* PAYLOAD_HASH */
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) return NULL;
    
    result->data = ngx_pnalloc(pool, len + 1);
    if (result->data == NULL) return NULL;
    
    result->len = ngx_sprintf(result->data, "%s\n%V\n%V\n%V\n%V\n%V%Z",
                              method, encoded_uri,
                              query ? query : &(ngx_str_t)ngx_null_string,
                              headers, signed_headers, payload_hash)
                  - result->data - 1;
    
    return result;
}

/* Build string to sign */
static ngx_str_t *
build_string_to_sign(ngx_pool_t *pool, ngx_str_t *amz_date, ngx_str_t *scope,
    ngx_str_t *canonical_hash)
{
    ngx_str_t *result;
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) return NULL;
    
    result->data = ngx_pnalloc(pool, 256 + canonical_hash->len);
    if (result->data == NULL) return NULL;
    
    result->len = ngx_sprintf(result->data, "%s\n%V\n%V\n%V%Z",
                              AWS_ALGORITHM, amz_date, scope, canonical_hash)
                  - result->data - 1;
    
    return result;
}

/* Sign a request and return Authorization header */
static ngx_str_t *
sign_request(ngx_pool_t *pool, cfml_s3_config_t *config, const char *method,
    ngx_str_t *uri, ngx_str_t *query, ngx_str_t *payload, time_t timestamp)
{
    u_char amz_date[20], date_stamp[12];
    ngx_str_t amz_date_str, date_str;
    ngx_str_t *payload_hash, *canonical_req, *canonical_hash;
    ngx_str_t *string_to_sign, *result;
    ngx_str_t scope, headers, signed_headers, host;
    u_char scope_buf[128], headers_buf[512];
    u_char *signing_key, *signature;
    unsigned int sig_len;
    
    /* Get timestamps */
    format_timestamp(amz_date, date_stamp, timestamp);
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    date_str.data = date_stamp;
    date_str.len = ngx_strlen(date_stamp);
    
    /* Build scope: date/region/s3/aws4_request */
    scope.data = scope_buf;
    scope.len = ngx_sprintf(scope_buf, "%s/%V/s3/%s%Z",
                            date_stamp, &config->region, AWS_REQUEST)
                - scope_buf - 1;
    
    /* Build host */
    if (config->path_style) {
        host = config->endpoint;
    } else {
        host.data = ngx_pnalloc(pool, config->bucket.len + config->endpoint.len + 2);
        host.len = ngx_sprintf(host.data, "%V.%V%Z",
                               &config->bucket, &config->endpoint) - host.data - 1;
    }
    
    /* Hash payload */
    if (payload && payload->len > 0) {
        payload_hash = sha256_hex(pool, payload->data, payload->len);
    } else {
        /* Empty string hash */
        payload_hash = sha256_hex(pool, (u_char *)"", 0);
    }
    if (payload_hash == NULL) return NULL;
    
    /* Build canonical headers (must be sorted) */
    headers.data = headers_buf;
    headers.len = ngx_sprintf(headers_buf, "host:%V\nx-amz-content-sha256:%V\nx-amz-date:%s\n%Z",
                              &host, payload_hash, amz_date) - headers_buf - 1;
    
    ngx_str_set(&signed_headers, "host;x-amz-content-sha256;x-amz-date");
    
    /* Build canonical request */
    canonical_req = build_canonical_request(pool, method, uri, query,
                                            &headers, &signed_headers, payload_hash);
    if (canonical_req == NULL) return NULL;
    
    /* Hash canonical request */
    canonical_hash = sha256_hex(pool, canonical_req->data, canonical_req->len);
    if (canonical_hash == NULL) return NULL;
    
    /* Build string to sign */
    string_to_sign = build_string_to_sign(pool, &amz_date_str, &scope, canonical_hash);
    if (string_to_sign == NULL) return NULL;
    
    /* Get signing key */
    signing_key = get_signing_key(pool, &config->secret_key, &date_str,
                                   &config->region, &sig_len);
    if (signing_key == NULL) return NULL;
    
    /* Calculate signature */
    signature = hmac_sha256_raw(pool, signing_key, sig_len,
                                 string_to_sign->data, string_to_sign->len, &sig_len);
    if (signature == NULL) return NULL;
    
    /* Build Authorization header */
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) return NULL;
    
    result->data = ngx_pnalloc(pool, 512);
    if (result->data == NULL) return NULL;
    
    /* Hex encode signature */
    u_char sig_hex[65];
    ngx_hex_dump(sig_hex, signature, 32);
    ngx_strlow(sig_hex, sig_hex, 64);
    sig_hex[64] = '\0';
    
    result->len = ngx_sprintf(result->data,
        "%s Credential=%V/%V, SignedHeaders=%V, Signature=%s%Z",
        AWS_ALGORITHM, &config->access_key, &scope, &signed_headers, sig_hex)
        - result->data - 1;
    
    return result;
}

/* ============= S3 Operations ============= */

ngx_int_t
cfml_s3_init(ngx_pool_t *pool, cfml_s3_config_t *config)
{
    s3_default_config = ngx_pcalloc(pool, sizeof(cfml_s3_config_t));
    if (s3_default_config == NULL) {
        return NGX_ERROR;
    }
    
    *s3_default_config = *config;
    return NGX_OK;
}

/* Build S3 URL */
static ngx_str_t *
build_s3_url(ngx_pool_t *pool, cfml_s3_config_t *config, ngx_str_t *key)
{
    ngx_str_t *url;
    ngx_str_t *encoded_key;
    
    encoded_key = uri_encode(pool, key, 0);
    if (encoded_key == NULL) return NULL;
    
    url = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (url == NULL) return NULL;
    
    url->data = ngx_pnalloc(pool, 512);
    if (url->data == NULL) return NULL;
    
    if (config->path_style) {
        url->len = ngx_sprintf(url->data, "https://%V/%V/%V%Z",
                               &config->endpoint, &config->bucket, encoded_key)
                   - url->data - 1;
    } else {
        url->len = ngx_sprintf(url->data, "https://%V.%V/%V%Z",
                               &config->bucket, &config->endpoint, encoded_key)
                   - url->data - 1;
    }
    
    return url;
}

ngx_int_t
cfml_s3_put(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key, ngx_str_t *data, ngx_str_t *content_type)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *url, *auth, uri;
    ngx_str_t header_name, *payload_hash;
    u_char amz_date[20], date_stamp[12];
    time_t now;
    
    if (config == NULL) {
        config = s3_default_config;
    }
    if (config == NULL) {
        return NGX_ERROR;
    }
    
    now = ngx_time();
    format_timestamp(amz_date, date_stamp, now);
    
    /* Build URI (just the key path) */
    uri.data = ngx_pnalloc(pool, key->len + 2);
    uri.len = ngx_sprintf(uri.data, "/%V%Z", key) - uri.data - 1;
    
    /* Sign the request */
    auth = sign_request(pool, config, "PUT", &uri, NULL, data, now);
    if (auth == NULL) {
        return NGX_ERROR;
    }
    
    /* Build full URL */
    url = build_s3_url(pool, config, key);
    if (url == NULL) {
        return NGX_ERROR;
    }
    
    /* Create HTTP request */
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NGX_ERROR;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_PUT;
    req->body = *data;
    
    /* Add headers */
    ngx_str_set(&header_name, "Authorization");
    cfml_http_add_header(req, &header_name, auth);
    
    ngx_str_set(&header_name, "x-amz-date");
    ngx_str_t amz_date_str;
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    cfml_http_add_header(req, &header_name, &amz_date_str);
    
    payload_hash = sha256_hex(pool, data->data, data->len);
    ngx_str_set(&header_name, "x-amz-content-sha256");
    cfml_http_add_header(req, &header_name, payload_hash);
    
    if (content_type && content_type->len > 0) {
        ngx_str_set(&header_name, "Content-Type");
        cfml_http_add_header(req, &header_name, content_type);
    }
    
    /* Execute request */
    resp = cfml_http_execute(req);
    if (resp == NULL) {
        return NGX_ERROR;
    }
    
    return (resp->status_code >= 200 && resp->status_code < 300) ? NGX_OK : NGX_ERROR;
}

ngx_str_t *
cfml_s3_get(ngx_pool_t *pool, cfml_s3_config_t *config, ngx_str_t *key)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *url, *auth, uri;
    ngx_str_t header_name, empty_hash;
    u_char amz_date[20], date_stamp[12];
    time_t now;
    ngx_str_t *result;
    
    if (config == NULL) {
        config = s3_default_config;
    }
    if (config == NULL) {
        return NULL;
    }
    
    now = ngx_time();
    format_timestamp(amz_date, date_stamp, now);
    
    /* Build URI */
    uri.data = ngx_pnalloc(pool, key->len + 2);
    uri.len = ngx_sprintf(uri.data, "/%V%Z", key) - uri.data - 1;
    
    /* Sign the request (empty payload for GET) */
    auth = sign_request(pool, config, "GET", &uri, NULL, NULL, now);
    if (auth == NULL) {
        return NULL;
    }
    
    url = build_s3_url(pool, config, key);
    if (url == NULL) {
        return NULL;
    }
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NULL;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_GET;
    
    /* Add headers */
    ngx_str_set(&header_name, "Authorization");
    cfml_http_add_header(req, &header_name, auth);
    
    ngx_str_set(&header_name, "x-amz-date");
    ngx_str_t amz_date_str;
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    cfml_http_add_header(req, &header_name, &amz_date_str);
    
    /* Empty payload hash */
    empty_hash = *sha256_hex(pool, (u_char *)"", 0);
    ngx_str_set(&header_name, "x-amz-content-sha256");
    cfml_http_add_header(req, &header_name, &empty_hash);
    
    resp = cfml_http_execute(req);
    if (resp == NULL || resp->status_code != 200) {
        return NULL;
    }
    
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) {
        return NULL;
    }
    
    *result = resp->content;
    return result;
}

ngx_int_t
cfml_s3_delete(ngx_pool_t *pool, cfml_s3_config_t *config, ngx_str_t *key)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *url, *auth, uri;
    ngx_str_t header_name, empty_hash;
    u_char amz_date[20], date_stamp[12];
    time_t now;
    
    if (config == NULL) {
        config = s3_default_config;
    }
    if (config == NULL) {
        return NGX_ERROR;
    }
    
    now = ngx_time();
    format_timestamp(amz_date, date_stamp, now);
    
    uri.data = ngx_pnalloc(pool, key->len + 2);
    uri.len = ngx_sprintf(uri.data, "/%V%Z", key) - uri.data - 1;
    
    auth = sign_request(pool, config, "DELETE", &uri, NULL, NULL, now);
    if (auth == NULL) {
        return NGX_ERROR;
    }
    
    url = build_s3_url(pool, config, key);
    if (url == NULL) {
        return NGX_ERROR;
    }
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NGX_ERROR;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_DELETE;
    
    ngx_str_set(&header_name, "Authorization");
    cfml_http_add_header(req, &header_name, auth);
    
    ngx_str_set(&header_name, "x-amz-date");
    ngx_str_t amz_date_str;
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    cfml_http_add_header(req, &header_name, &amz_date_str);
    
    empty_hash = *sha256_hex(pool, (u_char *)"", 0);
    ngx_str_set(&header_name, "x-amz-content-sha256");
    cfml_http_add_header(req, &header_name, &empty_hash);
    
    resp = cfml_http_execute(req);
    if (resp == NULL) {
        return NGX_ERROR;
    }
    
    return (resp->status_code >= 200 && resp->status_code < 300) ? NGX_OK : NGX_ERROR;
}

ngx_array_t *
cfml_s3_list(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *prefix, ngx_uint_t max_keys)
{
    cfml_http_request_t *req;
    cfml_http_response_t *resp;
    ngx_str_t *url, *auth, uri;
    ngx_str_t header_name, empty_hash, query;
    u_char query_buf[256];
    u_char amz_date[20], date_stamp[12];
    time_t now;
    ngx_array_t *result;
    
    if (config == NULL) {
        config = s3_default_config;
    }
    if (config == NULL) {
        return NULL;
    }
    
    now = ngx_time();
    format_timestamp(amz_date, date_stamp, now);
    
    ngx_str_set(&uri, "/");
    
    /* Build query string */
    query.data = query_buf;
    if (prefix && prefix->len > 0) {
        query.len = ngx_sprintf(query_buf, "list-type=2&max-keys=%ui&prefix=%V%Z",
                                max_keys > 0 ? max_keys : 1000, prefix) - query_buf - 1;
    } else {
        query.len = ngx_sprintf(query_buf, "list-type=2&max-keys=%ui%Z",
                                max_keys > 0 ? max_keys : 1000) - query_buf - 1;
    }
    
    auth = sign_request(pool, config, "GET", &uri, &query, NULL, now);
    if (auth == NULL) {
        return NULL;
    }
    
    /* Build URL with query */
    url = ngx_pcalloc(pool, sizeof(ngx_str_t));
    url->data = ngx_pnalloc(pool, 512);
    if (config->path_style) {
        url->len = ngx_sprintf(url->data, "https://%V/%V?%V%Z",
                               &config->endpoint, &config->bucket, &query)
                   - url->data - 1;
    } else {
        url->len = ngx_sprintf(url->data, "https://%V.%V?%V%Z",
                               &config->bucket, &config->endpoint, &query)
                   - url->data - 1;
    }
    
    req = cfml_http_request_create(pool);
    if (req == NULL) {
        return NULL;
    }
    
    req->url = *url;
    req->method = CFML_HTTP_GET;
    
    ngx_str_set(&header_name, "Authorization");
    cfml_http_add_header(req, &header_name, auth);
    
    ngx_str_set(&header_name, "x-amz-date");
    ngx_str_t amz_date_str;
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    cfml_http_add_header(req, &header_name, &amz_date_str);
    
    empty_hash = *sha256_hex(pool, (u_char *)"", 0);
    ngx_str_set(&header_name, "x-amz-content-sha256");
    cfml_http_add_header(req, &header_name, &empty_hash);
    
    resp = cfml_http_execute(req);
    if (resp == NULL || resp->status_code != 200) {
        return NULL;
    }
    
    /* Parse XML response - simplified, returns keys as strings */
    /* TODO: Full XML parsing for complete S3 object metadata */
    result = ngx_array_create(pool, 16, sizeof(cfml_s3_object_t));
    
    return result;
}

ngx_str_t *
cfml_s3_presign(ngx_pool_t *pool, cfml_s3_config_t *config,
    ngx_str_t *key, ngx_int_t expires_seconds, ngx_int_t is_put)
{
    ngx_str_t *result, *encoded_key;
    u_char amz_date[20], date_stamp[12];
    u_char scope_buf[128], cred_buf[256];
    ngx_str_t scope, credential, canonical_req, query;
    u_char query_buf[1024], canonical_buf[2048];
    time_t now;
    u_char *signing_key, *signature;
    unsigned int sig_len;
    ngx_str_t *canonical_hash, *string_to_sign;
    ngx_str_t amz_date_str, date_str;
    
    if (config == NULL) {
        config = s3_default_config;
    }
    if (config == NULL) {
        return NULL;
    }
    
    if (expires_seconds <= 0) {
        expires_seconds = 3600;  /* Default 1 hour */
    }
    if (expires_seconds > 604800) {
        expires_seconds = 604800;  /* Max 7 days */
    }
    
    now = ngx_time();
    format_timestamp(amz_date, date_stamp, now);
    amz_date_str.data = amz_date;
    amz_date_str.len = ngx_strlen(amz_date);
    date_str.data = date_stamp;
    date_str.len = ngx_strlen(date_stamp);
    
    /* Build scope and credential */
    scope.data = scope_buf;
    scope.len = ngx_sprintf(scope_buf, "%s/%V/s3/%s%Z",
                            date_stamp, &config->region, AWS_REQUEST) - scope_buf - 1;
    
    credential.data = cred_buf;
    credential.len = ngx_sprintf(cred_buf, "%V/%V%Z",
                                 &config->access_key, &scope) - cred_buf - 1;
    
    encoded_key = uri_encode(pool, key, 0);
    
    /* Build presigned URL query params */
    query.data = query_buf;
    query.len = ngx_sprintf(query_buf,
        "X-Amz-Algorithm=%s&"
        "X-Amz-Credential=%V&"
        "X-Amz-Date=%s&"
        "X-Amz-Expires=%d&"
        "X-Amz-SignedHeaders=host%Z",
        AWS_ALGORITHM, uri_encode(pool, &credential, 1),
        amz_date, (int)expires_seconds) - query_buf - 1;
    
    /* Build host */
    ngx_str_t host;
    if (config->path_style) {
        host = config->endpoint;
    } else {
        host.data = ngx_pnalloc(pool, config->bucket.len + config->endpoint.len + 2);
        host.len = ngx_sprintf(host.data, "%V.%V%Z",
                               &config->bucket, &config->endpoint) - host.data - 1;
    }
    
    /* Build canonical request for presigned URL */
    canonical_req.data = canonical_buf;
    canonical_req.len = ngx_sprintf(canonical_buf,
        "%s\n/%V\n%V\nhost:%V\n\nhost\nUNSIGNED-PAYLOAD%Z",
        is_put ? "PUT" : "GET", encoded_key, &query, &host) - canonical_buf - 1;
    
    canonical_hash = sha256_hex(pool, canonical_req.data, canonical_req.len);
    if (canonical_hash == NULL) return NULL;
    
    string_to_sign = build_string_to_sign(pool, &amz_date_str, &scope, canonical_hash);
    if (string_to_sign == NULL) return NULL;
    
    signing_key = get_signing_key(pool, &config->secret_key, &date_str,
                                   &config->region, &sig_len);
    if (signing_key == NULL) return NULL;
    
    signature = hmac_sha256_raw(pool, signing_key, sig_len,
                                 string_to_sign->data, string_to_sign->len, &sig_len);
    if (signature == NULL) return NULL;
    
    /* Hex encode signature */
    u_char sig_hex[65];
    ngx_hex_dump(sig_hex, signature, 32);
    ngx_strlow(sig_hex, sig_hex, 64);
    sig_hex[64] = '\0';
    
    /* Build final URL */
    result = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (result == NULL) return NULL;
    
    result->data = ngx_pnalloc(pool, 2048);
    if (result->data == NULL) return NULL;
    
    if (config->path_style) {
        result->len = ngx_sprintf(result->data,
            "https://%V/%V/%V?%V&X-Amz-Signature=%s%Z",
            &config->endpoint, &config->bucket, encoded_key,
            &query, sig_hex) - result->data - 1;
    } else {
        result->len = ngx_sprintf(result->data,
            "https://%V.%V/%V?%V&X-Amz-Signature=%s%Z",
            &config->bucket, &config->endpoint, encoded_key,
            &query, sig_hex) - result->data - 1;
    }
    
    return result;
}

/* ============= CFML Function implementations ============= */

cfml_value_t *
cfml_func_s3put(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t content_type;
    ngx_int_t rc;
    
    if (args == NULL || args->nelts < 2) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING || argv[1]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    ngx_str_null(&content_type);
    if (args->nelts >= 3 && argv[2]->type == CFML_TYPE_STRING) {
        content_type = argv[2]->data.string;
    }
    
    rc = cfml_s3_put(ctx->pool, NULL, &argv[0]->data.string,
                      &argv[1]->data.string, &content_type);
    
    return cfml_create_boolean(ctx->pool, rc == NGX_OK);
}

cfml_value_t *
cfml_func_s3get(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *data;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_null(ctx->pool);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_null(ctx->pool);
    }
    
    data = cfml_s3_get(ctx->pool, NULL, &argv[0]->data.string);
    if (data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    return cfml_create_string(ctx->pool, data);
}

cfml_value_t *
cfml_func_s3delete(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_int_t rc;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    rc = cfml_s3_delete(ctx->pool, NULL, &argv[0]->data.string);
    return cfml_create_boolean(ctx->pool, rc == NGX_OK);
}

cfml_value_t *
cfml_func_s3list(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t prefix;
    ngx_uint_t max_keys = 1000;
    ngx_array_t *objects;
    cfml_value_t *result;
    cfml_s3_object_t *obj;
    ngx_uint_t i;
    
    ngx_str_null(&prefix);
    
    if (args != NULL && args->nelts >= 1) {
        argv = args->elts;
        if (argv[0]->type == CFML_TYPE_STRING) {
            prefix = argv[0]->data.string;
        }
        if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_INTEGER) {
            max_keys = (ngx_uint_t)argv[1]->data.integer;
        }
    }
    
    objects = cfml_s3_list(ctx->pool, NULL, &prefix, max_keys);
    
    result = cfml_create_array(ctx->pool);
    if (objects != NULL) {
        obj = objects->elts;
        for (i = 0; i < objects->nelts; i++) {
            cfml_value_t *item = cfml_create_struct(ctx->pool);
            ngx_str_t key_name;
            
            ngx_str_set(&key_name, "key");
            cfml_struct_set(item->data.structure, &key_name,
                cfml_create_string(ctx->pool, &obj[i].key));
            
            ngx_str_set(&key_name, "size");
            cfml_struct_set(item->data.structure, &key_name,
                cfml_create_integer(ctx->pool, (int64_t)obj[i].size));
            
            ngx_str_set(&key_name, "lastModified");
            cfml_struct_set(item->data.structure, &key_name,
                cfml_create_integer(ctx->pool, (int64_t)obj[i].last_modified));
            
            cfml_array_append(result->data.array, item);
        }
    }
    
    return result;
}

cfml_value_t *
cfml_func_s3presign(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t **argv;
    ngx_str_t *url;
    ngx_int_t expires = 3600;
    ngx_int_t is_put = 0;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    argv = args->elts;
    
    if (argv[0]->type != CFML_TYPE_STRING) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_INTEGER) {
        expires = (ngx_int_t)argv[1]->data.integer;
    }
    
    if (args->nelts >= 3 && argv[2]->type == CFML_TYPE_BOOLEAN) {
        is_put = argv[2]->data.boolean;
    }
    
    url = cfml_s3_presign(ctx->pool, NULL, &argv[0]->data.string, expires, is_put);
    if (url == NULL) {
        return cfml_create_string_cstr(ctx->pool, "");
    }
    
    return cfml_create_string(ctx->pool, url);
}
