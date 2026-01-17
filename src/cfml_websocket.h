/*
 * CFML WebSocket - WebSocket protocol support
 * Note: Full WebSocket requires nginx upgrade handling
 */

#ifndef _CFML_WEBSOCKET_H_
#define _CFML_WEBSOCKET_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* WebSocket opcodes */
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} cfml_ws_opcode_t;

/* WebSocket frame */
typedef struct {
    cfml_ws_opcode_t    opcode;
    unsigned            fin:1;
    unsigned            masked:1;
    u_char              mask[4];
    ngx_str_t           payload;
} cfml_ws_frame_t;

/* WebSocket connection */
typedef struct {
    ngx_pool_t          *pool;
    ngx_connection_t    *connection;
    unsigned            handshake_complete:1;
    unsigned            closing:1;
    ngx_str_t           protocol;
} cfml_ws_conn_t;

/* Check if request is WebSocket upgrade */
ngx_int_t cfml_ws_is_upgrade_request(ngx_http_request_t *r);

/* Perform WebSocket handshake */
ngx_int_t cfml_ws_handshake(ngx_http_request_t *r, cfml_ws_conn_t **conn);

/* Send WebSocket frame */
ngx_int_t cfml_ws_send(cfml_ws_conn_t *conn, ngx_str_t *data, cfml_ws_opcode_t opcode);

/* Send text message */
ngx_int_t cfml_ws_send_text(cfml_ws_conn_t *conn, ngx_str_t *text);

/* Send binary message */
ngx_int_t cfml_ws_send_binary(cfml_ws_conn_t *conn, ngx_str_t *data);

/* Send ping */
ngx_int_t cfml_ws_ping(cfml_ws_conn_t *conn);

/* Send pong */
ngx_int_t cfml_ws_pong(cfml_ws_conn_t *conn, ngx_str_t *data);

/* Close connection */
ngx_int_t cfml_ws_close(cfml_ws_conn_t *conn, uint16_t code, ngx_str_t *reason);

/* CFML functions */
cfml_value_t *cfml_func_wsaccept(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_wssend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_wsclose(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_WEBSOCKET_H_ */
