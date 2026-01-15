/*
 * CFML Component - CFC handling
 */

#ifndef _CFML_COMPONENT_H_
#define _CFML_COMPONENT_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Component loading */
cfml_component_t *cfml_component_load(cfml_context_t *ctx, ngx_str_t *path);
cfml_component_t *cfml_component_create(cfml_context_t *ctx, ngx_str_t *name);
cfml_component_t *cfml_component_new(cfml_context_t *ctx, ngx_str_t *path,
                                     ngx_array_t *init_args);

/* Component instantiation */
cfml_value_t *cfml_component_instantiate(cfml_context_t *ctx, 
                                         cfml_component_t *comp,
                                         ngx_array_t *init_args);

/* Method invocation */
cfml_value_t *cfml_component_invoke(cfml_context_t *ctx, cfml_component_t *comp,
                                    ngx_str_t *method, ngx_array_t *args);
cfml_value_t *cfml_component_invoke_static(cfml_context_t *ctx, ngx_str_t *comp_path,
                                           ngx_str_t *method, ngx_array_t *args);

/* Property access */
cfml_value_t *cfml_component_get_property(cfml_component_t *comp, ngx_str_t *name);
ngx_int_t cfml_component_set_property(cfml_component_t *comp, ngx_str_t *name,
                                      cfml_value_t *value);

/* Function management */
ngx_int_t cfml_component_add_function(cfml_component_t *comp, cfml_function_t *func);
cfml_function_t *cfml_component_get_function(cfml_component_t *comp, ngx_str_t *name);
ngx_int_t cfml_component_has_function(cfml_component_t *comp, ngx_str_t *name);

/* Inheritance */
ngx_int_t cfml_component_extends(cfml_context_t *ctx, cfml_component_t *comp,
                                 ngx_str_t *parent_path);
ngx_int_t cfml_component_implements(cfml_context_t *ctx, cfml_component_t *comp,
                                    ngx_str_t *interface_path);

/* Metadata */
cfml_struct_t *cfml_component_get_metadata(cfml_component_t *comp);
cfml_struct_t *cfml_function_get_metadata(cfml_function_t *func);

/* Function execution */
cfml_value_t *cfml_function_call(cfml_context_t *ctx, cfml_function_t *func,
                                 ngx_array_t *args);
cfml_value_t *cfml_closure_call(cfml_context_t *ctx, cfml_function_t *closure,
                                ngx_array_t *args);

/* Argument handling */
ngx_int_t cfml_function_bind_arguments(cfml_context_t *ctx, cfml_function_t *func,
                                       ngx_array_t *args);
ngx_int_t cfml_function_validate_arguments(cfml_function_t *func, ngx_array_t *args);

/* Component path resolution */
ngx_int_t cfml_resolve_component_path(cfml_context_t *ctx, ngx_str_t *name,
                                      ngx_str_t *resolved_path);
ngx_int_t cfml_component_exists(cfml_context_t *ctx, ngx_str_t *path);

/* Component cache */
cfml_component_t *cfml_component_cache_get(ngx_str_t *path);
ngx_int_t cfml_component_cache_put(ngx_str_t *path, cfml_component_t *comp);

#endif /* _CFML_COMPONENT_H_ */
