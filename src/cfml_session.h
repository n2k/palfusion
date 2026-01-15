/*
 * CFML Session - Session management
 */

#ifndef _CFML_SESSION_H_
#define _CFML_SESSION_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Session initialization */
ngx_int_t cfml_session_init(ngx_cycle_t *cycle);
void cfml_session_cleanup(ngx_cycle_t *cycle);

/* Session operations */
ngx_int_t cfml_session_start(cfml_context_t *ctx, ngx_str_t *session_id);
ngx_int_t cfml_session_end(cfml_context_t *ctx);
ngx_int_t cfml_session_rotate_id(cfml_context_t *ctx);

/* Session data */
ngx_int_t cfml_session_get(cfml_context_t *ctx, ngx_str_t *key, cfml_value_t **value);
ngx_int_t cfml_session_set(cfml_context_t *ctx, ngx_str_t *key, cfml_value_t *value);
ngx_int_t cfml_session_delete(cfml_context_t *ctx, ngx_str_t *key);
ngx_int_t cfml_session_clear(cfml_context_t *ctx);
cfml_struct_t *cfml_session_get_all(cfml_context_t *ctx);

/* Session ID operations */
ngx_int_t cfml_session_generate_id(ngx_pool_t *pool, ngx_str_t *id);
ngx_int_t cfml_session_validate_id(ngx_str_t *id);
ngx_int_t cfml_session_get_cookie(cfml_context_t *ctx, ngx_str_t *cookie_value);
ngx_int_t cfml_session_set_cookie(cfml_context_t *ctx, ngx_str_t *session_id);

/* Session timeout */
ngx_int_t cfml_session_touch(cfml_context_t *ctx);
ngx_int_t cfml_session_is_expired(cfml_context_t *ctx);
ngx_int_t cfml_session_set_timeout(cfml_context_t *ctx, ngx_msec_t timeout);

/* Application scope */
ngx_int_t cfml_application_init(cfml_context_t *ctx, ngx_str_t *app_name);
ngx_int_t cfml_application_get(cfml_context_t *ctx, ngx_str_t *key, 
                               cfml_value_t **value);
ngx_int_t cfml_application_set(cfml_context_t *ctx, ngx_str_t *key,
                               cfml_value_t *value);
ngx_int_t cfml_application_delete(cfml_context_t *ctx, ngx_str_t *key);
ngx_int_t cfml_application_clear(cfml_context_t *ctx);
cfml_struct_t *cfml_application_get_all(cfml_context_t *ctx);

/* Server scope */
ngx_int_t cfml_server_scope_init(void);
cfml_struct_t *cfml_server_scope_get(void);

/* Client scope (requires client storage or database) */
ngx_int_t cfml_client_init(cfml_context_t *ctx, ngx_str_t *client_id);
ngx_int_t cfml_client_get(cfml_context_t *ctx, ngx_str_t *key, cfml_value_t **value);
ngx_int_t cfml_client_set(cfml_context_t *ctx, ngx_str_t *key, cfml_value_t *value);

#endif /* _CFML_SESSION_H_ */
