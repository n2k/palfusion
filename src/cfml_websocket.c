/*
 * CFML WebSocket - Full RFC 6455 WebSocket implementation
 * Integrates with nginx event loop for bidirectional communication
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>
#include "cfml_websocket.h"
#include "cfml_json.h"
#include "cfml_variables.h"

/* WebSocket GUID for handshake */
static const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* Connection registry for lookups */
#define MAX_WS_CONNECTIONS 1024
static cfml_ws_conn_t *ws_connections[MAX_WS_CONNECTIONS];
static ngx_uint_t ws_conn_count = 0;

/* Forward declarations */
static void ws_read_handler(ngx_event_t *ev);
static void ws_write_handler(ngx_event_t *ev);
static ngx_int_t ws_process_frame(cfml_ws_conn_t *conn);

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

/* Register connection */
static void
ws_register_connection(cfml_ws_conn_t *conn)
{
    ngx_uint_t i;
    
    for (i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (ws_connections[i] == NULL) {
            ws_connections[i] = conn;
            ws_conn_count++;
            return;
        }
    }
}

/* Unregister connection */
static void
ws_unregister_connection(cfml_ws_conn_t *conn)
{
    ngx_uint_t i;
    
    for (i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (ws_connections[i] == conn) {
            ws_connections[i] = NULL;
            ws_conn_count--;
            return;
        }
    }
}

/* Cleanup handler */
static void
ws_cleanup_handler(void *data)
{
    cfml_ws_conn_t *conn = data;
    
    ws_unregister_connection(conn);
    
    if (conn->on_close) {
        conn->on_close(conn, 1001, NULL);
    }
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
    ngx_pool_cleanup_t *cln;
    
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
    ws->request = r;
    
    /* Allocate receive buffer */
    ws->recv_buf = ngx_create_temp_buf(r->pool, 65536);
    if (ws->recv_buf == NULL) {
        return NGX_ERROR;
    }
    
    /* Initialize frame state */
    ws->frame.fin = 0;
    ws->frame.opcode = 0;
    ws->frame.masked = 0;
    ws->frame.payload_len = 0;
    
    /* Register cleanup */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln) {
        cln->handler = ws_cleanup_handler;
        cln->data = ws;
    }
    
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
    
    /* Set up event handlers for bidirectional communication */
    r->connection->read->handler = ws_read_handler;
    r->connection->write->handler = ws_write_handler;
    r->connection->data = ws;
    
    /* Add read event */
    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    
    /* Register connection */
    ws_register_connection(ws);
    
    *conn = ws;
    
    return NGX_OK;
}

/* Decode masked payload */
static void
ws_unmask_payload(u_char *payload, size_t len, u_char *mask)
{
    size_t i;
    
    for (i = 0; i < len; i++) {
        payload[i] ^= mask[i % 4];
    }
}

/* Read handler - called when data available */
static void
ws_read_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    cfml_ws_conn_t *ws;
    ssize_t n;
    
    c = ev->data;
    ws = c->data;
    
    if (ws == NULL || ws->closing) {
        return;
    }
    
    /* Read available data into buffer */
    n = c->recv(c, ws->recv_buf->last, ws->recv_buf->end - ws->recv_buf->last);
    
    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            cfml_ws_close(ws, 1001, NULL);
        }
        return;
    }
    
    if (n == 0 || n == NGX_ERROR) {
        /* Connection closed */
        cfml_ws_close(ws, 1001, NULL);
        return;
    }
    
    ws->recv_buf->last += n;
    
    /* Process frames */
    while (ws_process_frame(ws) == NGX_OK) {
        /* Continue processing */
    }
    
    /* Re-add read event */
    if (!ws->closing) {
        ngx_handle_read_event(c->read, 0);
    }
}

/* Process a single WebSocket frame */
static ngx_int_t
ws_process_frame(cfml_ws_conn_t *ws)
{
    u_char *p;
    size_t available, header_len, payload_len;
    u_char mask[4];
    ngx_str_t payload;
    
    p = ws->recv_buf->pos;
    available = ws->recv_buf->last - ws->recv_buf->pos;
    
    /* Need at least 2 bytes for header */
    if (available < 2) {
        return NGX_AGAIN;
    }
    
    /* Parse header */
    ws->frame.fin = (p[0] >> 7) & 1;
    ws->frame.opcode = p[0] & 0x0F;
    ws->frame.masked = (p[1] >> 7) & 1;
    payload_len = p[1] & 0x7F;
    
    header_len = 2;
    
    /* Extended payload length */
    if (payload_len == 126) {
        if (available < 4) return NGX_AGAIN;
        payload_len = (p[2] << 8) | p[3];
        header_len = 4;
    } else if (payload_len == 127) {
        if (available < 10) return NGX_AGAIN;
        /* 64-bit length - use lower 32 bits for sanity */
        payload_len = (p[6] << 24) | (p[7] << 16) | (p[8] << 8) | p[9];
        header_len = 10;
    }
    
    /* Mask key (client messages must be masked) */
    if (ws->frame.masked) {
        if (available < header_len + 4) return NGX_AGAIN;
        ngx_memcpy(mask, p + header_len, 4);
        header_len += 4;
    }
    
    /* Check if full payload available */
    if (available < header_len + payload_len) {
        return NGX_AGAIN;
    }
    
    /* Extract and unmask payload */
    payload.data = p + header_len;
    payload.len = payload_len;
    
    if (ws->frame.masked) {
        ws_unmask_payload(payload.data, payload.len, mask);
    }
    
    ws->frame.payload_len = payload_len;
    
    /* Handle frame by opcode */
    switch (ws->frame.opcode) {
    case WS_OPCODE_TEXT:
    case WS_OPCODE_BINARY:
        /* Data frame - call message handler */
        if (ws->on_message) {
            ws->on_message(ws, &payload, ws->frame.opcode == WS_OPCODE_BINARY);
        }
        break;
        
    case WS_OPCODE_CLOSE:
        /* Close frame */
        ws->closing = 1;
        if (payload.len >= 2) {
            uint16_t code = (payload.data[0] << 8) | payload.data[1];
            ngx_str_t reason;
            reason.data = payload.data + 2;
            reason.len = payload.len - 2;
            if (ws->on_close) {
                ws->on_close(ws, code, &reason);
            }
        }
        /* Echo close frame */
        cfml_ws_close(ws, 1000, NULL);
        break;
        
    case WS_OPCODE_PING:
        /* Respond with pong */
        cfml_ws_pong(ws, &payload);
        break;
        
    case WS_OPCODE_PONG:
        /* Pong received - update keepalive */
        ws->last_pong = ngx_time();
        break;
        
    default:
        /* Unknown opcode */
        break;
    }
    
    /* Advance buffer position */
    ws->recv_buf->pos = p + header_len + payload_len;
    
    /* Compact buffer if needed */
    if (ws->recv_buf->pos == ws->recv_buf->last) {
        ws->recv_buf->pos = ws->recv_buf->start;
        ws->recv_buf->last = ws->recv_buf->start;
    }
    
    return NGX_OK;
}

/* Write handler */
static void
ws_write_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    cfml_ws_conn_t *ws;
    
    c = ev->data;
    ws = c->data;
    
    if (ws == NULL) {
        return;
    }
    
    /* Flush pending output */
    if (ws->send_chain) {
        ws->send_chain = c->send_chain(c, ws->send_chain, 0);
        
        if (ws->send_chain == NGX_CHAIN_ERROR) {
            cfml_ws_close(ws, 1001, NULL);
            return;
        }
    }
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
    
    /* Send immediately */
    cl = conn->connection->send_chain(conn->connection, cl, 0);
    
    if (cl == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }
    
    /* If not fully sent, queue for later */
    if (cl != NULL) {
        if (conn->send_chain == NULL) {
            conn->send_chain = cl;
        } else {
            ngx_chain_t *last = conn->send_chain;
            while (last->next) {
                last = last->next;
            }
            last->next = cl;
        }
        
        ngx_handle_write_event(conn->connection->write, 0);
    }
    
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
    conn->last_ping = ngx_time();
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
    
    if (conn->closing && conn->close_sent) {
        /* Already sent close, just finish */
        ws_unregister_connection(conn);
        ngx_http_finalize_request(conn->request, NGX_HTTP_CLOSE);
        return NGX_OK;
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
    
    conn->close_sent = 1;
    cfml_ws_send(conn, &close_data, WS_OPCODE_CLOSE);
    
    return NGX_OK;
}

/* Send JSON message */
ngx_int_t
cfml_ws_send_json(cfml_ws_conn_t *conn, cfml_value_t *value)
{
    ngx_str_t *json;
    
    json = cfml_json_serialize(conn->pool, value);
    if (json == NULL) {
        return NGX_ERROR;
    }
    
    return cfml_ws_send_text(conn, json);
}

/* Broadcast to all connections */
ngx_int_t
cfml_ws_broadcast(ngx_str_t *data, cfml_ws_opcode_t opcode)
{
    ngx_uint_t i;
    
    for (i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (ws_connections[i] != NULL && ws_connections[i]->handshake_complete) {
            cfml_ws_send(ws_connections[i], data, opcode);
        }
    }
    
    return NGX_OK;
}

/* Get connection count */
ngx_uint_t
cfml_ws_connection_count(void)
{
    return ws_conn_count;
}

/* ============= CFML function implementations ============= */

/* Store connection in request context for later use */
static cfml_ws_conn_t *
get_ws_connection(cfml_context_t *ctx)
{
    /* Connection would be stored in request context */
    return ctx->r->connection->data;
}

cfml_value_t *cfml_func_wsaccept(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_ws_conn_t *conn;
    cfml_value_t *result;
    (void)args;
    
    if (!cfml_ws_is_upgrade_request(ctx->r)) {
        result = cfml_create_struct(ctx->pool);
        ngx_str_t key;
        ngx_str_set(&key, "success");
        cfml_struct_set(result->data.structure, &key, 
            cfml_create_boolean(ctx->pool, 0));
        ngx_str_set(&key, "error");
        cfml_struct_set(result->data.structure, &key,
            cfml_create_string_cstr(ctx->pool, "Not a WebSocket upgrade request"));
        return result;
    }
    
    if (cfml_ws_handshake(ctx->r, &conn) != NGX_OK) {
        result = cfml_create_struct(ctx->pool);
        ngx_str_t key;
        ngx_str_set(&key, "success");
        cfml_struct_set(result->data.structure, &key,
            cfml_create_boolean(ctx->pool, 0));
        ngx_str_set(&key, "error");
        cfml_struct_set(result->data.structure, &key,
            cfml_create_string_cstr(ctx->pool, "Handshake failed"));
        return result;
    }
    
    result = cfml_create_struct(ctx->pool);
    ngx_str_t key;
    ngx_str_set(&key, "success");
    cfml_struct_set(result->data.structure, &key,
        cfml_create_boolean(ctx->pool, 1));
    ngx_str_set(&key, "connectionId");
    cfml_struct_set(result->data.structure, &key,
        cfml_create_integer(ctx->pool, (int64_t)(uintptr_t)conn));
    
    return result;
}

cfml_value_t *cfml_func_wssend(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_ws_conn_t *conn;
    cfml_value_t **argv;
    ngx_int_t rc;
    
    conn = get_ws_connection(ctx);
    if (conn == NULL || !conn->handshake_complete) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type == CFML_TYPE_STRING) {
        rc = cfml_ws_send_text(conn, &argv[0]->data.string);
    } else if (argv[0]->type == CFML_TYPE_STRUCT || argv[0]->type == CFML_TYPE_ARRAY) {
        rc = cfml_ws_send_json(conn, argv[0]);
    } else if (argv[0]->type == CFML_TYPE_INTEGER) {
        /* Convert integer to string */
        ngx_str_t str;
        u_char buf[64];
        str.data = buf;
        str.len = ngx_sprintf(buf, "%L%Z", argv[0]->data.integer) - buf - 1;
        rc = cfml_ws_send_text(conn, &str);
    } else if (argv[0]->type == CFML_TYPE_FLOAT) {
        /* Convert float to string */
        ngx_str_t str;
        u_char buf[64];
        str.data = buf;
        str.len = ngx_sprintf(buf, "%f%Z", argv[0]->data.floating) - buf - 1;
        rc = cfml_ws_send_text(conn, &str);
    } else {
        rc = NGX_ERROR;
    }
    
    return cfml_create_boolean(ctx->pool, rc == NGX_OK);
}

cfml_value_t *cfml_func_wsclose(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_ws_conn_t *conn;
    cfml_value_t **argv;
    uint16_t code = 1000;
    ngx_str_t *reason = NULL;
    
    conn = get_ws_connection(ctx);
    if (conn == NULL) {
        return cfml_create_boolean(ctx->pool, 0);
    }
    
    if (args != NULL && args->nelts >= 1) {
        argv = args->elts;
        if (argv[0]->type == CFML_TYPE_INTEGER) {
            code = (uint16_t)argv[0]->data.integer;
        }
        if (args->nelts >= 2 && argv[1]->type == CFML_TYPE_STRING) {
            reason = &argv[1]->data.string;
        }
    }
    
    cfml_ws_close(conn, code, reason);
    return cfml_create_boolean(ctx->pool, 1);
}

/* Broadcast function */
cfml_value_t *cfml_func_wsbroadcast(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t **argv;
    ngx_str_t *json;
    
    if (args == NULL || args->nelts < 1) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    argv = args->elts;
    
    if (argv[0]->type == CFML_TYPE_STRING) {
        cfml_ws_broadcast(&argv[0]->data.string, WS_OPCODE_TEXT);
    } else {
        json = cfml_json_serialize(ctx->pool, argv[0]);
        if (json) {
            cfml_ws_broadcast(json, WS_OPCODE_TEXT);
        }
    }
    
    return cfml_create_integer(ctx->pool, (int64_t)ws_conn_count);
}
