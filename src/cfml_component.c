/*
 * CFML Component - CFC handling implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_component.h"
#include "cfml_parser.h"
#include "cfml_runtime.h"
#include "cfml_variables.h"

cfml_component_t *
cfml_component_load(cfml_context_t *ctx, ngx_str_t *path)
{
    cfml_template_t *tmpl;
    cfml_component_t *comp;

    tmpl = cfml_parse_template(ctx->pool, path, 1);
    if (tmpl == NULL) {
        return NULL;
    }

    comp = ngx_pcalloc(ctx->pool, sizeof(cfml_component_t));
    if (comp == NULL) {
        return NULL;
    }

    comp->full_path = *path;
    comp->pool = ctx->pool;
    comp->this_scope = cfml_struct_new(ctx->pool);
    comp->properties = ngx_array_create(ctx->pool, 8, sizeof(cfml_property_t));

    /* Execute component to register functions */
    cfml_component_t *saved = ctx->current_component;
    ctx->current_component = comp;
    cfml_execute(ctx, tmpl->root);
    ctx->current_component = saved;

    return comp;
}

cfml_component_t *
cfml_component_create(cfml_context_t *ctx, ngx_str_t *name)
{
    cfml_component_t *comp;

    comp = ngx_pcalloc(ctx->pool, sizeof(cfml_component_t));
    if (comp == NULL) {
        return NULL;
    }

    comp->name = *name;
    comp->pool = ctx->pool;
    comp->this_scope = cfml_struct_new(ctx->pool);
    comp->properties = ngx_array_create(ctx->pool, 8, sizeof(cfml_property_t));

    return comp;
}

cfml_value_t *
cfml_component_instantiate(cfml_context_t *ctx, cfml_component_t *comp,
                           ngx_array_t *init_args)
{
    cfml_value_t *instance;

    if (comp == NULL) {
        return cfml_create_null(ctx->pool);
    }

    instance = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    if (instance == NULL) {
        return cfml_create_null(ctx->pool);
    }

    instance->type = CFML_TYPE_COMPONENT;
    instance->data.component = comp;
    instance->pool = ctx->pool;

    /* Call init method if exists */
    if (cfml_component_has_function(comp, &(ngx_str_t)ngx_string("init"))) {
        cfml_component_invoke(ctx, comp, &(ngx_str_t)ngx_string("init"), init_args);
    }

    return instance;
}

cfml_value_t *
cfml_component_invoke(cfml_context_t *ctx, cfml_component_t *comp,
                      ngx_str_t *method, ngx_array_t *args)
{
    cfml_function_t *func;

    func = cfml_component_get_function(comp, method);
    if (func == NULL) {
        ngx_str_set(&ctx->error_message, "Method not found");
        return cfml_create_null(ctx->pool);
    }

    return cfml_function_call(ctx, func, args);
}

cfml_value_t *
cfml_component_invoke_static(cfml_context_t *ctx, ngx_str_t *comp_path,
                             ngx_str_t *method, ngx_array_t *args)
{
    cfml_component_t *comp = cfml_component_load(ctx, comp_path);
    if (comp == NULL) {
        return cfml_create_null(ctx->pool);
    }
    return cfml_component_invoke(ctx, comp, method, args);
}

cfml_value_t *
cfml_component_get_property(cfml_component_t *comp, ngx_str_t *name)
{
    if (comp == NULL || comp->this_scope == NULL) {
        return NULL;
    }
    return cfml_struct_get(comp->this_scope, name);
}

ngx_int_t
cfml_component_set_property(cfml_component_t *comp, ngx_str_t *name,
                            cfml_value_t *value)
{
    if (comp == NULL || comp->this_scope == NULL) {
        return NGX_ERROR;
    }
    return cfml_struct_set(comp->this_scope, name, value);
}

ngx_int_t
cfml_component_add_function(cfml_component_t *comp, cfml_function_t *func)
{
    func->owner = comp;
    return cfml_struct_set(comp->this_scope, &func->name, 
        (cfml_value_t*)func);  /* Simplified */
}

cfml_function_t *
cfml_component_get_function(cfml_component_t *comp, ngx_str_t *name)
{
    cfml_value_t *val;
    
    if (comp == NULL || comp->this_scope == NULL) {
        return NULL;
    }
    
    val = cfml_struct_get(comp->this_scope, name);
    if (val != NULL && val->type == CFML_TYPE_FUNCTION) {
        return val->data.function;
    }
    
    return NULL;
}

ngx_int_t
cfml_component_has_function(cfml_component_t *comp, ngx_str_t *name)
{
    return cfml_component_get_function(comp, name) != NULL;
}

ngx_int_t
cfml_component_extends(cfml_context_t *ctx, cfml_component_t *comp,
                       ngx_str_t *parent_path)
{
    cfml_component_t *parent = cfml_component_load(ctx, parent_path);
    if (parent == NULL) {
        return NGX_ERROR;
    }
    comp->parent = parent;
    comp->extends = *parent_path;
    return NGX_OK;
}

ngx_int_t
cfml_component_implements(cfml_context_t *ctx, cfml_component_t *comp,
                          ngx_str_t *interface_path)
{
    comp->implements = *interface_path;
    return NGX_OK;
}

cfml_struct_t *
cfml_component_get_metadata(cfml_component_t *comp)
{
    /* Return component metadata as struct */
    return comp->this_scope;
}

cfml_struct_t *
cfml_function_get_metadata(cfml_function_t *func)
{
    return NULL;  /* Stub */
}

cfml_value_t *
cfml_function_call(cfml_context_t *ctx, cfml_function_t *func,
                   ngx_array_t *args)
{
    cfml_struct_t *saved_local;
    cfml_struct_t *saved_args;
    cfml_value_t *result;

    if (func == NULL) {
        return cfml_create_null(ctx->pool);
    }

    /* Save current scopes */
    saved_local = ctx->local_scope;
    saved_args = ctx->arguments_scope;

    /* Create new scopes */
    ctx->local_scope = cfml_struct_new(ctx->pool);
    ctx->arguments_scope = cfml_struct_new(ctx->pool);

    /* Bind arguments */
    cfml_function_bind_arguments(ctx, func, args);

    /* Execute function body */
    ctx->return_ = 0;
    ctx->return_value = NULL;
    cfml_execute_children(ctx, func->body);

    result = ctx->return_value;
    if (result == NULL) {
        result = cfml_create_null(ctx->pool);
    }

    /* Restore scopes */
    ctx->local_scope = saved_local;
    ctx->arguments_scope = saved_args;
    ctx->return_ = 0;

    return result;
}

cfml_value_t *
cfml_closure_call(cfml_context_t *ctx, cfml_function_t *closure,
                  ngx_array_t *args)
{
    return cfml_function_call(ctx, closure, args);
}

ngx_int_t
cfml_function_bind_arguments(cfml_context_t *ctx, cfml_function_t *func,
                             ngx_array_t *args)
{
    cfml_argument_def_t *defs;
    cfml_value_t **arg_vals;
    ngx_uint_t i;

    if (func->arguments == NULL || args == NULL) {
        return NGX_OK;
    }

    defs = func->arguments->elts;
    arg_vals = args->elts;

    for (i = 0; i < func->arguments->nelts; i++) {
        cfml_value_t *val;

        if (i < args->nelts) {
            val = arg_vals[i];
        } else if (defs[i].default_value != NULL) {
            val = defs[i].default_value;
        } else if (defs[i].required) {
            ngx_str_set(&ctx->error_message, "Required argument missing");
            return NGX_ERROR;
        } else {
            val = cfml_create_null(ctx->pool);
        }

        cfml_struct_set(ctx->arguments_scope, &defs[i].name, val);
    }

    return NGX_OK;
}

ngx_int_t
cfml_function_validate_arguments(cfml_function_t *func, ngx_array_t *args)
{
    return NGX_OK;
}

ngx_int_t
cfml_resolve_component_path(cfml_context_t *ctx, ngx_str_t *name,
                            ngx_str_t *resolved_path)
{
    /* Convert dot notation to path */
    u_char *p;
    ngx_uint_t i;

    resolved_path->len = name->len + 5;  /* .cfc + potential path adjustments */
    resolved_path->data = ngx_pnalloc(ctx->pool, resolved_path->len + 1);
    if (resolved_path->data == NULL) {
        return NGX_ERROR;
    }

    p = resolved_path->data;
    for (i = 0; i < name->len; i++) {
        if (name->data[i] == '.') {
            *p++ = '/';
        } else {
            *p++ = name->data[i];
        }
    }
    p = ngx_cpymem(p, ".cfc", 4);
    *p = '\0';
    resolved_path->len = p - resolved_path->data;

    return NGX_OK;
}

ngx_int_t
cfml_component_exists(cfml_context_t *ctx, ngx_str_t *path)
{
    ngx_file_info_t fi;
    return ngx_file_info(path->data, &fi) != NGX_FILE_ERROR;
}

cfml_component_t *cfml_component_cache_get(ngx_str_t *path) { return NULL; }
ngx_int_t cfml_component_cache_put(ngx_str_t *path, cfml_component_t *comp) { return NGX_OK; }

/* Value duplication */
cfml_value_t *
cfml_value_duplicate(ngx_pool_t *pool, cfml_value_t *value)
{
    cfml_value_t *copy;

    if (value == NULL) {
        return cfml_create_null(pool);
    }

    copy = ngx_pcalloc(pool, sizeof(cfml_value_t));
    if (copy == NULL) {
        return NULL;
    }

    *copy = *value;
    copy->pool = pool;

    /* Deep copy for complex types */
    switch (value->type) {
    case CFML_TYPE_STRING:
        copy->data.string.data = ngx_pnalloc(pool, value->data.string.len + 1);
        ngx_memcpy(copy->data.string.data, value->data.string.data, value->data.string.len);
        copy->data.string.data[value->data.string.len] = '\0';
        break;
    case CFML_TYPE_ARRAY:
        copy->data.array = cfml_array_new(pool, cfml_array_len(value->data.array));
        /* Deep copy elements */
        break;
    case CFML_TYPE_STRUCT:
        copy->data.structure = cfml_struct_copy(pool, value->data.structure);
        break;
    default:
        break;
    }

    return copy;
}
