/*
 * CFML Tags - Tag handler implementations
 */

#ifndef _CFML_TAGS_H_
#define _CFML_TAGS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Tag handler type */
typedef ngx_int_t (*cfml_tag_handler_t)(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Get tag handler by name */
cfml_tag_handler_t cfml_get_tag_handler(ngx_str_t *tag_name);

/* Core tags */
ngx_int_t cfml_tag_set(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_output(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_if(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_loop(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_break(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_continue(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_include(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_param(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Function/Component tags */
ngx_int_t cfml_tag_function(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_argument(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_return(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_component(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_property(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_invoke(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_invokeargument(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Data tags */
ngx_int_t cfml_tag_query(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_queryparam(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_storedproc(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_procparam(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_procresult(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_transaction(cfml_context_t *ctx, cfml_ast_node_t *node);

/* HTTP tags */
ngx_int_t cfml_tag_http(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_httpparam(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_location(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_header(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_content(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_cookie(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Control flow tags */
ngx_int_t cfml_tag_switch(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_case(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_defaultcase(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_try(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_catch(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_finally(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_throw(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_rethrow(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Output control tags */
ngx_int_t cfml_tag_abort(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_exit(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_dump(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_log(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_savecontent(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_silent(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_flush(cfml_context_t *ctx, cfml_ast_node_t *node);

/* File/Directory tags */
ngx_int_t cfml_tag_file(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_directory(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Mail tags */
ngx_int_t cfml_tag_mail(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_mailparam(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_mailpart(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Locking tags */
ngx_int_t cfml_tag_lock(cfml_context_t *ctx, cfml_ast_node_t *node);
ngx_int_t cfml_tag_thread(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Cache tags */
ngx_int_t cfml_tag_cache(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Settings tag */
ngx_int_t cfml_tag_setting(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Schedule tag */
ngx_int_t cfml_tag_schedule(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Script tag */
ngx_int_t cfml_tag_script(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Module tag (custom tags) */
ngx_int_t cfml_tag_module(cfml_context_t *ctx, cfml_ast_node_t *node);

/* Helper functions */
ngx_str_t *cfml_get_tag_attribute(cfml_ast_node_t *node, const char *name);
cfml_value_t *cfml_eval_tag_attribute(cfml_context_t *ctx, cfml_ast_node_t *node,
                                       const char *name);
ngx_int_t cfml_has_tag_attribute(cfml_ast_node_t *node, const char *name);

#endif /* _CFML_TAGS_H_ */
