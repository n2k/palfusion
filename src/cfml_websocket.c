/*
 * CFML WebSocket - WebSocket protocol implementation
 * Note: Full implementation requires nginx upstream module integration
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>
#include "cfml_websocket.h"
#include "cfml_variables.h"

/* WebSocket GUID for handshake */
static const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* Check if request is WebSocket upgrade */
ngx_int_t
cfml_ws_is_upgrade_request(ngx_http_request_t *r)
{
    ngx_table_elt_t *upgrade, *connection;
    
    /* Check Upgrade header */
    upgrade = r->headers_in.upgrade;
    if (upgrade == NULL || upgrade->value.len != 9 ||
        ngx_strncasecmp(upgrade->value.data, (u_char *)"websocket", 9) != 0) {
        return 0;
    }
    
    /* Check Connection header contains "upgrade" */
    connection = r->headers_in.connection;
    if (connection == NULL) {
        return 0;
    }
    
    if (ngx_strcasestrn(connection->value.data, "upgrade", 7 - 1) == NULL) {
        return 0;
    }
    
    return 1;
}

/* Base64 encode */
static ngx_str_t *
ws_base64_encode(ngx_pool_t *pool, u_char *data, size_t len)
{
    ngx_str_t src, *dst;
    
    src.data = data;
    src.len = len;
    
    dst = ngx_pcalloc(pool, sizeof(ngx_str_t));
    if (dst == NULL) {
        return NULL;
    }
    
    dst->len = ngx_base64_encoded_length(len);
    dst->data = ngx_pnalloc(pool, dst->len + 1);
    if (dst->data == NULL) {
        return NULL;
    }
    
    ngx_encode_base64(dst, &src);
    dst->data[dst->len] = '\0';
    
    return dst;
}

/* Generate accept key */
static ngx_str_t *
ws_generate_accept_key(ngx_pool_t *pool, ngx_str_t *key)
{
    u_char hash[SHA_DIGEST_LENGTH];
    u_char combined[256];
    size_t combined_len;
    SHA_CTX sha;
    
    /* Combine key with GUID */
    combined_len = key->len + ngx_strlen(WS_GUID);
    if (combined_len >= sizeof(combined)) {
        return NULL;
    }
    
    ngx_memcpy(combined, key->data, key->len);
    ngx_memcpy(combined + key->len, WS_GUID, ngx_strlen(WS_GUID));
    
    /* SHA-1 hash */
    SHA1_Init(&sha);
    SHA1_Update(&sha, combined, combined_len);
    SHA1_Final(hash, &sha);
    
    /* Base64 encode */
    return ws_base64_encode(pool, hash, SHA_DIGEST_LENGTH);
}

/* Perform WebSocket handshake */
ngx_int_t
cfml_ws_handshake(ngx_http_request_t *r, cfml_ws_conn_t **conn)
{
    ngx_table_elt_t *h;
    ngx_str_t *ws_key, *accept_key;
    cfml_ws_conn_t *ws;
    ngx_list_part_t *part;
    ngx_uint_t i;
    
    /* Find Sec-WebSocket-Key header */
    ws_key = NULL;
    part = &r->headers_in.headers.part;
    h = part->elts;
    
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        
        if (h[i].key.len == 17 &&
            ngx_strncasecmp(h[i].key.data, (u_char *)"Sec-WebSocket-Key", 17) == 0) {
            ws_key = &h[i].value;
            break;
        }
    }
    
    if (ws_key == NULL) {
        return NGX_ERROR;
    }
    
    /* Generate accept key */
    accept_key = ws_generate_accept_key(r->pool, ws_key);
    if (accept_key == NULL) {
        return NGX_ERROR;
    }
    
    /* Create connection context */
    ws = ngx_pcalloc(r->pool, sizeof(cfml_ws_conn_t));
    if (ws == NULL) {
        return NGX_ERROR;
    }
    
    ws->pool = r->pool;
    ws->connection = r->connection;
    
    /* Send handshake response */
    r->headers_out.status = NGX_HTTP_SWITCHING_PROTOCOLS;
    
    /* Upgrade header */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Upgrade");
    ngx_str_set(&h->value, "websocket");
    h->hash = 1;
    
    /* Connection header */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Connection");
    ngx_str_set(&h->value, "Upgrade");
    h->hash = 1;
    
    /* Sec-WebSocket-Accept header */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Sec-WebSocket-Accept");
    h->value = *accept_key;
    h->hash = 1;
    
    ngx_http_send_header(r);
    
    ws->handshake_complete = 1;
    *conn = ws;
    
    return NGX_OK;
}

/* Encode WebSocket frame */
static ngx_chain_t *
ws_encode_frame(ngx_pool_t *pool, ngx_str_t *payload, cfml_ws_opcode_t opcode)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    size_t frame_len;
    u_char *p;
    
    /* Calculate frame size */
    frame_len = 2;  /* Minimum header */
    if (payload->len > 125) {
        if (payload->len > 65535) {
            frame_len += 8;
        } else {
            frame_len += 2;
        }
    }
    frame_len += payload->len;
    
    b = ngx_create_temp_buf(pool, frame_len);
    if (b == NULL) {
        return NULL;
    }
    
    p = b->last;
    
    /* First byte: FIN + opcode */
    *p++ = 0x80 | (opcode & 0x0F);  /* FIN=1 */
    
    /* Second byte: length (no mask from server) */
    if (payload->len <= 125) {
        *p++ = payload->len;
    } else if (payload->len <= 65535) {
        *p++ = 126;
        *p++ = (payload->len >> 8) & 0xFF;
        *p++ = payload->len & 0xFF;
    } else {
        *p++ = 127;
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
        *p++ = (payload->len >> 24) & 0xFF;
        *p++ = (payload->len >> 16) & 0xFF;
        *p++ = (payload->len >> 8) & 0xFF;
        *p++ = payload->len & 0xFF;
    }
    
    /* Payload */
    p = ngx_copy(p, payload->data, payload->len);
    
    b->last = p;
    
    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }
    
    cl->buf = b;
    cl->next = NULL;
    
    return cl;
}

/* Send WebSocket frame */
ngx_int_t
cfml_ws_send(cfml_ws_conn_t *conn, ngx_str_t *data, cfml_ws_opcode_t opcode)
{
    ngx_chain_t *cl;
    
    if (conn == NULL || !conn->handshake_complete || conn->closing) {
        return NGX_ERROR;
    }
    
    cl = ws_encode_frame(conn->pool, data, opcode);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    
    /* Note: In a real implementation, this would use the connection's
     * send chain. For now, this is a stub. */
    return NGX_OK;
}

ngx_int_t cfml_ws_send_text(cfml_ws_conn_t *conn, ngx_str_t *text) {
    return cfml_ws_send(conn, text, WS_OPCODE_TEXT);
}

ngx_int_t cfml_ws_send_binary(cfml_ws_conn_t *conn, ngx_str_t *data) {
    return cfml_ws_send(conn, data, WS_OPCODE_BINARY);
}

ngx_int_t cfml_ws_ping(cfml_ws_conn_t *conn) {
    ngx_str_t empty = ngx_null_string;
    return cfml_ws_send(conn, &empty, WS_OPCODE_PING);
}

ngx_int_t cfml_ws_pong(cfml_ws_conn_t *conn, ngx_str_t *data) {
    return cfml_ws_send(conn, data, WS_OPCODE_PONG);
}

ngx_int_t cfml_ws_close(cfml_ws_conn_t *conn, uint16_t code, ngx_str_t *reason) {
    ngx_str_t close_data;
    u_char buf[128];
    
    if (conn == NULL) {
        return NGX_ERROR;
    }
    
    conn->closing = 1;
    
    /* Build close frame payload */
    close_data.data = buf;
    buf[0] = (code >> 8) & 0xFF;
    buf[1] = code & 0xFF;
    close_data.len = 2;
    
    if (reason && reason->len > 0 && reason->len < 123) {
        ngx_memcpy(buf + 2, reason->data, reason->len);
        close_data.len += reason->len;
    }
    
    return cfml_ws_send(conn, &close_data, WS_OPCODE_CLOSE);
}

/* CFML function implementations */
cfml_value_t *cfml_func_wsaccept(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_ws_conn_t *conn;
    (void)args;
    
    if (!cfml_ws_is_upgrade_request(ctx->r)) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    if (cfml_ws_handshake(ctx->r, &conn) != NGX_OK) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    return cfml_create_boolean(ctx->pool, 1);
}

cfml_value_t *cfml_func_wssend(cfml_context_t *ctx, ngx_array_t *args) {
    (void)args;
    /* Would require persistent connection context */
    return cfml_create_boolean(ctx->pool, 0);
}

cfml_value_t *cfml_func_wsclose(cfml_context_t *ctx, ngx_array_t *args) {
    (void)args;
    return cfml_create_boolean(ctx->pool, 0);
}
