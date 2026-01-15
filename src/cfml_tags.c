/*
 * CFML Tags - Tag handler implementations
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_tags.h"
#include "cfml_parser.h"
#include "cfml_runtime.h"
#include "cfml_variables.h"
#include "cfml_expression.h"

/* Tag handler registry */
typedef struct {
    ngx_str_t           name;
    cfml_tag_handler_t  handler;
} cfml_tag_def_t;

static cfml_tag_def_t cfml_tag_handlers[] = {
    { ngx_string("set"), cfml_tag_set },
    { ngx_string("output"), cfml_tag_output },
    { ngx_string("if"), cfml_tag_if },
    { ngx_string("loop"), cfml_tag_loop },
    { ngx_string("break"), cfml_tag_break },
    { ngx_string("continue"), cfml_tag_continue },
    { ngx_string("include"), cfml_tag_include },
    { ngx_string("param"), cfml_tag_param },
    { ngx_string("function"), cfml_tag_function },
    { ngx_string("argument"), cfml_tag_argument },
    { ngx_string("return"), cfml_tag_return },
    { ngx_string("component"), cfml_tag_component },
    { ngx_string("query"), cfml_tag_query },
    { ngx_string("http"), cfml_tag_http },
    { ngx_string("try"), cfml_tag_try },
    { ngx_string("throw"), cfml_tag_throw },
    { ngx_string("switch"), cfml_tag_switch },
    { ngx_string("abort"), cfml_tag_abort },
    { ngx_string("exit"), cfml_tag_exit },
    { ngx_string("dump"), cfml_tag_dump },
    { ngx_string("log"), cfml_tag_log },
    { ngx_string("location"), cfml_tag_location },
    { ngx_string("header"), cfml_tag_header },
    { ngx_string("content"), cfml_tag_content },
    { ngx_string("cookie"), cfml_tag_cookie },
    { ngx_string("savecontent"), cfml_tag_savecontent },
    { ngx_string("file"), cfml_tag_file },
    { ngx_string("directory"), cfml_tag_directory },
    { ngx_string("mail"), cfml_tag_mail },
    { ngx_string("lock"), cfml_tag_lock },
    { ngx_string("setting"), cfml_tag_setting },
    { ngx_string("silent"), cfml_tag_silent },
    { ngx_string("flush"), cfml_tag_flush },
    { ngx_null_string, NULL }
};

/* Get tag handler by name */
cfml_tag_handler_t
cfml_get_tag_handler(ngx_str_t *tag_name)
{
    cfml_tag_def_t *def;

    for (def = cfml_tag_handlers; def->name.len > 0; def++) {
        if (tag_name->len == def->name.len &&
            ngx_strncasecmp(tag_name->data, def->name.data, tag_name->len) == 0) {
            return def->handler;
        }
    }

    return NULL;
}

/* Helper: Get string attribute value */
ngx_str_t *
cfml_get_tag_attribute(cfml_ast_node_t *node, const char *name)
{
    cfml_ast_attr_t *attrs;
    ngx_uint_t i;
    size_t name_len = ngx_strlen(name);

    attrs = node->attributes->elts;
    for (i = 0; i < node->attributes->nelts; i++) {
        if (attrs[i].name.len == name_len &&
            ngx_strncasecmp(attrs[i].name.data, (u_char *)name, name_len) == 0) {
            if (attrs[i].value && attrs[i].value->data.literal) {
                return &attrs[i].value->data.literal->data.string;
            }
        }
    }

    return NULL;
}

/* Helper: Evaluate attribute as expression */
cfml_value_t *
cfml_eval_tag_attribute(cfml_context_t *ctx, cfml_ast_node_t *node,
                        const char *name)
{
    cfml_ast_attr_t *attrs;
    ngx_uint_t i;
    size_t name_len = ngx_strlen(name);
    ngx_str_t *attr_str;
    ngx_str_t interpolated;

    attrs = node->attributes->elts;
    for (i = 0; i < node->attributes->nelts; i++) {
        if (attrs[i].name.len == name_len &&
            ngx_strncasecmp(attrs[i].name.data, (u_char *)name, name_len) == 0) {
            if (attrs[i].value == NULL) {
                return cfml_create_boolean(ctx->pool, 1);  /* Flag attribute */
            }
            
            if (attrs[i].value->type == CFML_AST_EXPR_LITERAL &&
                attrs[i].value->data.literal->type == CFML_TYPE_STRING) {
                /* Interpolate the string value */
                attr_str = &attrs[i].value->data.literal->data.string;
                if (cfml_interpolate_string(ctx, attr_str, &interpolated) == NGX_OK) {
                    return cfml_create_string(ctx->pool, &interpolated);
                }
                return attrs[i].value->data.literal;
            }
            
            return cfml_eval_expression(ctx, attrs[i].value);
        }
    }

    return NULL;
}

/* Helper: Check if attribute exists */
ngx_int_t
cfml_has_tag_attribute(cfml_ast_node_t *node, const char *name)
{
    return cfml_get_tag_attribute(node, name) != NULL;
}

/* ===== Tag Implementations ===== */

/* cfset - Variable assignment */
ngx_int_t
cfml_tag_set(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    /* The body of cfset is an expression to evaluate */
    if (node->children->nelts > 0) {
        cfml_ast_node_t **children = node->children->elts;
        cfml_eval_expression(ctx, children[0]);
    }

    return NGX_OK;
}

/* cfoutput - Output with variable interpolation */
ngx_int_t
cfml_tag_output(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *query_name;
    cfml_value_t *query_val;
    cfml_query_t *query = NULL;
    ngx_uint_t start_row = 1, end_row;

    /* Check for query attribute */
    query_name = cfml_get_tag_attribute(node, "query");
    if (query_name != NULL) {
        query_val = cfml_get_variable(ctx, query_name);
        if (query_val != NULL && query_val->type == CFML_TYPE_QUERY) {
            query = query_val->data.query;
        }
    }

    /* Check for startrow/maxrows */
    cfml_value_t *startrow_val = cfml_eval_tag_attribute(ctx, node, "startrow");
    cfml_value_t *maxrows_val = cfml_eval_tag_attribute(ctx, node, "maxrows");

    if (startrow_val != NULL) {
        int64_t sr;
        cfml_value_to_integer(startrow_val, &sr);
        start_row = (ngx_uint_t)sr;
    }

    if (query != NULL) {
        /* Query loop */
        end_row = query->row_count;
        
        if (maxrows_val != NULL) {
            int64_t mr;
            cfml_value_to_integer(maxrows_val, &mr);
            if (start_row + mr - 1 < end_row) {
                end_row = start_row + mr - 1;
            }
        }

        for (query->current_row = start_row; 
             query->current_row <= end_row; 
             query->current_row++) {
            
            if (cfml_execute_children(ctx, node) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ctx->break_) {
                ctx->break_ = 0;
                break;
            }
            if (ctx->continue_) {
                ctx->continue_ = 0;
                continue;
            }
        }
    } else {
        /* Simple output - execute children */
        return cfml_execute_children(ctx, node);
    }

    return NGX_OK;
}

/* cfif - Conditional execution */
ngx_int_t
cfml_tag_if(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *condition;
    cfml_ast_node_t **children;
    ngx_uint_t i;
    ngx_int_t executed = 0;

    /* Evaluate condition */
    condition = cfml_eval_tag_attribute(ctx, node, "condition");
    if (condition == NULL) {
        /* Try to get condition from first child if it's an expression */
        /* ... */
    }

    if (condition != NULL && cfml_value_to_boolean(condition)) {
        /* Execute if body */
        children = node->children->elts;
        for (i = 0; i < node->children->nelts; i++) {
            if (children[i]->type == CFML_AST_TAG_ELSEIF ||
                children[i]->type == CFML_AST_TAG_ELSE) {
                break;
            }
            if (cfml_execute(ctx, children[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        executed = 1;
    }

    if (!executed) {
        /* Check for elseif/else */
        children = node->children->elts;
        for (i = 0; i < node->children->nelts; i++) {
            if (children[i]->type == CFML_AST_TAG_ELSEIF) {
                condition = cfml_eval_tag_attribute(ctx, children[i], "condition");
                if (condition != NULL && cfml_value_to_boolean(condition)) {
                    return cfml_execute_children(ctx, children[i]);
                }
            } else if (children[i]->type == CFML_AST_TAG_ELSE) {
                return cfml_execute_children(ctx, children[i]);
            }
        }
    }

    return NGX_OK;
}

/* cfloop - Loop construct */
ngx_int_t
cfml_tag_loop(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *index_var, *from_str, *to_str, *step_str;
    ngx_str_t *list_str, *item_var, *delimiters;
    ngx_str_t *array_name, *struct_name, *query_name;
    ngx_str_t *condition_str;
    cfml_value_t *val;
    int64_t from_val, to_val, step_val, i;

    /* Index loop: from/to */
    from_str = cfml_get_tag_attribute(node, "from");
    to_str = cfml_get_tag_attribute(node, "to");
    index_var = cfml_get_tag_attribute(node, "index");

    if (from_str != NULL && to_str != NULL) {
        val = cfml_eval_tag_attribute(ctx, node, "from");
        cfml_value_to_integer(val, &from_val);
        
        val = cfml_eval_tag_attribute(ctx, node, "to");
        cfml_value_to_integer(val, &to_val);

        step_val = 1;
        step_str = cfml_get_tag_attribute(node, "step");
        if (step_str != NULL) {
            val = cfml_eval_tag_attribute(ctx, node, "step");
            cfml_value_to_integer(val, &step_val);
        }

        if (step_val == 0) {
            ngx_str_set(&ctx->error_message, "Loop step cannot be zero");
            return NGX_ERROR;
        }

        for (i = from_val; 
             (step_val > 0) ? (i <= to_val) : (i >= to_val);
             i += step_val) {
            
            if (index_var != NULL) {
                cfml_set_variable(ctx, index_var, 
                                  cfml_create_integer(ctx->pool, i));
            }

            if (cfml_execute_children(ctx, node) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ctx->break_) {
                ctx->break_ = 0;
                break;
            }
            if (ctx->continue_) {
                ctx->continue_ = 0;
                continue;
            }
        }

        return NGX_OK;
    }

    /* List loop */
    list_str = cfml_get_tag_attribute(node, "list");
    item_var = cfml_get_tag_attribute(node, "index");
    if (item_var == NULL) {
        item_var = cfml_get_tag_attribute(node, "item");
    }

    if (list_str != NULL) {
        val = cfml_eval_tag_attribute(ctx, node, "list");
        ngx_str_t list_val;
        cfml_value_to_string(ctx, val, &list_val);

        delimiters = cfml_get_tag_attribute(node, "delimiters");
        u_char delim = ',';
        if (delimiters != NULL && delimiters->len > 0) {
            delim = delimiters->data[0];
        }

        u_char *p = list_val.data;
        u_char *end = list_val.data + list_val.len;
        u_char *start;
        ngx_str_t item;
        ngx_int_t list_index = 0;

        while (p <= end) {
            /* Skip leading delimiters/whitespace */
            while (p < end && (*p == delim || *p == ' ' || *p == '\t')) {
                p++;
            }
            
            start = p;
            while (p < end && *p != delim) {
                p++;
            }

            if (p > start || p == end) {
                item.data = start;
                item.len = p - start;

                /* Trim trailing whitespace */
                while (item.len > 0 && 
                       (item.data[item.len - 1] == ' ' || 
                        item.data[item.len - 1] == '\t')) {
                    item.len--;
                }

                list_index++;
                
                if (item_var != NULL) {
                    cfml_set_variable(ctx, item_var,
                                      cfml_create_string(ctx->pool, &item));
                }

                if (cfml_execute_children(ctx, node) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ctx->break_) {
                    ctx->break_ = 0;
                    break;
                }
                if (ctx->continue_) {
                    ctx->continue_ = 0;
                }
            }

            if (p < end) {
                p++;  /* Skip delimiter */
            }
        }

        return NGX_OK;
    }

    /* Array loop */
    array_name = cfml_get_tag_attribute(node, "array");
    if (array_name != NULL) {
        val = cfml_eval_tag_attribute(ctx, node, "array");
        if (val != NULL && val->type == CFML_TYPE_ARRAY) {
            cfml_value_t **items = val->data.array->items->elts;
            ngx_uint_t arr_i;
            
            index_var = cfml_get_tag_attribute(node, "index");
            item_var = cfml_get_tag_attribute(node, "item");

            for (arr_i = 0; arr_i < val->data.array->items->nelts; arr_i++) {
                if (index_var != NULL) {
                    cfml_set_variable(ctx, index_var,
                                      cfml_create_integer(ctx->pool, arr_i + 1));
                }
                if (item_var != NULL) {
                    cfml_set_variable(ctx, item_var, items[arr_i]);
                }

                if (cfml_execute_children(ctx, node) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ctx->break_) {
                    ctx->break_ = 0;
                    break;
                }
                if (ctx->continue_) {
                    ctx->continue_ = 0;
                }
            }
        }
        return NGX_OK;
    }

    /* Struct loop */
    struct_name = cfml_get_tag_attribute(node, "collection");
    if (struct_name == NULL) {
        struct_name = cfml_get_tag_attribute(node, "struct");
    }
    
    if (struct_name != NULL) {
        val = cfml_eval_tag_attribute(ctx, node, "collection");
        if (val == NULL) {
            val = cfml_eval_tag_attribute(ctx, node, "struct");
        }
        
        if (val != NULL && val->type == CFML_TYPE_STRUCT) {
            ngx_str_t *key_var = cfml_get_tag_attribute(node, "item");
            cfml_struct_entry_t *entries = val->data.structure->entries->elts;
            ngx_uint_t struct_i;

            for (struct_i = 0; struct_i < val->data.structure->entries->nelts; struct_i++) {
                if (key_var != NULL) {
                    cfml_set_variable(ctx, key_var,
                                      cfml_create_string(ctx->pool, &entries[struct_i].key));
                }

                if (cfml_execute_children(ctx, node) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ctx->break_) {
                    ctx->break_ = 0;
                    break;
                }
                if (ctx->continue_) {
                    ctx->continue_ = 0;
                }
            }
        }
        return NGX_OK;
    }

    /* Condition loop */
    condition_str = cfml_get_tag_attribute(node, "condition");
    if (condition_str != NULL) {
        while (1) {
            val = cfml_eval_tag_attribute(ctx, node, "condition");
            if (!cfml_value_to_boolean(val)) {
                break;
            }

            if (cfml_execute_children(ctx, node) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ctx->break_) {
                ctx->break_ = 0;
                break;
            }
            if (ctx->continue_) {
                ctx->continue_ = 0;
            }
        }
        return NGX_OK;
    }

    /* Query loop (handled in cfoutput mainly) */
    query_name = cfml_get_tag_attribute(node, "query");
    if (query_name != NULL) {
        val = cfml_get_variable(ctx, query_name);
        if (val != NULL && val->type == CFML_TYPE_QUERY) {
            cfml_query_t *q = val->data.query;
            
            for (q->current_row = 1; q->current_row <= q->row_count; q->current_row++) {
                if (cfml_execute_children(ctx, node) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ctx->break_) {
                    ctx->break_ = 0;
                    break;
                }
                if (ctx->continue_) {
                    ctx->continue_ = 0;
                }
            }
        }
        return NGX_OK;
    }

    return NGX_OK;
}

/* cfbreak */
ngx_int_t
cfml_tag_break(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ctx->break_ = 1;
    return NGX_OK;
}

/* cfcontinue */
ngx_int_t
cfml_tag_continue(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ctx->continue_ = 1;
    return NGX_OK;
}

/* cfinclude */
ngx_int_t
cfml_tag_include(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *template_path;
    cfml_value_t *val;
    ngx_str_t path;

    template_path = cfml_get_tag_attribute(node, "template");
    if (template_path == NULL) {
        ngx_str_set(&ctx->error_message, "cfinclude requires template attribute");
        return NGX_ERROR;
    }

    val = cfml_eval_tag_attribute(ctx, node, "template");
    if (cfml_value_to_string(ctx, val, &path) != NGX_OK) {
        return NGX_ERROR;
    }

    return cfml_include_template(ctx, &path);
}

/* cfparam */
ngx_int_t
cfml_tag_param(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *name;
    cfml_value_t *default_val, *existing;

    name = cfml_get_tag_attribute(node, "name");
    if (name == NULL) {
        ngx_str_set(&ctx->error_message, "cfparam requires name attribute");
        return NGX_ERROR;
    }

    /* Check if variable exists */
    existing = cfml_get_variable(ctx, name);
    if (existing != NULL && !existing->is_null) {
        return NGX_OK;
    }

    /* Set default value if provided */
    default_val = cfml_eval_tag_attribute(ctx, node, "default");
    if (default_val != NULL) {
        cfml_set_variable(ctx, name, default_val);
    } else {
        /* No default and variable doesn't exist - error */
        ngx_str_set(&ctx->error_message, "Variable is undefined and no default provided");
        ctx->error_line = node->line;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* cffunction */
ngx_int_t
cfml_tag_function(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *name;
    cfml_function_t *func;
    cfml_value_t *func_val;

    name = cfml_get_tag_attribute(node, "name");
    if (name == NULL) {
        ngx_str_set(&ctx->error_message, "cffunction requires name attribute");
        return NGX_ERROR;
    }

    /* Create function object */
    func = ngx_pcalloc(ctx->pool, sizeof(cfml_function_t));
    if (func == NULL) {
        return NGX_ERROR;
    }

    func->name = *name;
    func->body = node;
    func->pool = ctx->pool;
    func->arguments = ngx_array_create(ctx->pool, 8, sizeof(cfml_argument_def_t));

    /* Get return type */
    ngx_str_t *return_type = cfml_get_tag_attribute(node, "returntype");
    if (return_type != NULL) {
        func->return_type = *return_type;
    }

    /* Get access level */
    ngx_str_t *access = cfml_get_tag_attribute(node, "access");
    if (access != NULL) {
        func->access = *access;
    } else {
        ngx_str_set(&func->access, "public");
    }

    /* Parse argument definitions from children */
    cfml_ast_node_t **children = node->children->elts;
    ngx_uint_t i;
    for (i = 0; i < node->children->nelts; i++) {
        if (children[i]->type == CFML_AST_TAG_ARGUMENT) {
            cfml_argument_def_t *arg = ngx_array_push(func->arguments);
            if (arg == NULL) {
                return NGX_ERROR;
            }

            ngx_str_t *arg_name = cfml_get_tag_attribute(children[i], "name");
            if (arg_name != NULL) {
                arg->name = *arg_name;
            }

            arg->required = cfml_has_tag_attribute(children[i], "required");
            arg->default_value = cfml_eval_tag_attribute(ctx, children[i], "default");
        }
    }

    /* Store function in variables scope */
    func_val = ngx_pcalloc(ctx->pool, sizeof(cfml_value_t));
    func_val->type = CFML_TYPE_FUNCTION;
    func_val->data.function = func;
    func_val->pool = ctx->pool;

    cfml_set_variable(ctx, name, func_val);

    return NGX_OK;
}

/* cfargument */
ngx_int_t
cfml_tag_argument(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    /* Arguments are processed by cffunction */
    return NGX_OK;
}

/* cfreturn */
ngx_int_t
cfml_tag_return(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *val = NULL;

    /* Evaluate return expression from children */
    if (node->children->nelts > 0) {
        cfml_ast_node_t **children = node->children->elts;
        val = cfml_eval_expression(ctx, children[0]);
    }

    ctx->return_ = 1;
    ctx->return_value = val;

    return NGX_OK;
}

/* cfabort */
ngx_int_t
cfml_tag_abort(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ctx->abort = 1;
    return NGX_OK;
}

/* cfexit */
ngx_int_t
cfml_tag_exit(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ctx->exit = 1;
    return NGX_OK;
}

/* cfdump */
ngx_int_t
cfml_tag_dump(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *var;
    ngx_str_t output;
    ngx_str_t dump_str;

    var = cfml_eval_tag_attribute(ctx, node, "var");
    if (var == NULL) {
        return NGX_OK;
    }

    if (cfml_dump_value(ctx, var, &dump_str) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Output dump HTML */
    output.data = ngx_pnalloc(ctx->pool, dump_str.len + 100);
    output.len = ngx_sprintf(output.data, 
        "<div style=\"background:#f0f0f0;border:1px solid #ccc;padding:10px;margin:10px;\">"
        "<pre>%V</pre></div>", &dump_str) - output.data;

    return cfml_output_string(ctx, &output);
}

/* cflog */
ngx_int_t
cfml_tag_log(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *text_val;
    ngx_str_t text;

    text_val = cfml_eval_tag_attribute(ctx, node, "text");
    if (text_val == NULL) {
        return NGX_OK;
    }

    cfml_value_to_string(ctx, text_val, &text);

    ngx_log_error(NGX_LOG_INFO, ctx->r->connection->log, 0,
                  "CFML LOG: %V", &text);

    return NGX_OK;
}

/* cflocation - Redirect */
ngx_int_t
cfml_tag_location(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *url_val;
    ngx_str_t url;
    ngx_table_elt_t *location;
    ngx_int_t status = NGX_HTTP_MOVED_TEMPORARILY;

    url_val = cfml_eval_tag_attribute(ctx, node, "url");
    if (url_val == NULL) {
        ngx_str_set(&ctx->error_message, "cflocation requires url attribute");
        return NGX_ERROR;
    }

    cfml_value_to_string(ctx, url_val, &url);

    /* Check for statuscode attribute */
    cfml_value_t *status_val = cfml_eval_tag_attribute(ctx, node, "statuscode");
    if (status_val != NULL) {
        int64_t sc;
        cfml_value_to_integer(status_val, &sc);
        status = (ngx_int_t)sc;
    }

    /* Set Location header */
    location = ngx_list_push(&ctx->r->headers_out.headers);
    if (location == NULL) {
        return NGX_ERROR;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value.len = url.len;
    location->value.data = ngx_pstrdup(ctx->pool, &url);
    if (location->value.data == NULL) {
        return NGX_ERROR;
    }

    ctx->r->headers_out.location = location;
    ctx->r->headers_out.status = status;
    ctx->abort = 1;

    return NGX_OK;
}

/* cfheader */
ngx_int_t
cfml_tag_header(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *name;
    cfml_value_t *value_val;
    ngx_str_t value;
    ngx_table_elt_t *h;

    name = cfml_get_tag_attribute(node, "name");
    value_val = cfml_eval_tag_attribute(ctx, node, "value");

    if (name == NULL || value_val == NULL) {
        /* Check for statuscode */
        cfml_value_t *status_val = cfml_eval_tag_attribute(ctx, node, "statuscode");
        if (status_val != NULL) {
            int64_t sc;
            cfml_value_to_integer(status_val, &sc);
            ctx->r->headers_out.status = (ngx_uint_t)sc;
        }
        return NGX_OK;
    }

    cfml_value_to_string(ctx, value_val, &value);

    h = ngx_list_push(&ctx->r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key = *name;
    h->value = value;

    return NGX_OK;
}

/* cfcontent */
ngx_int_t
cfml_tag_content(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *type_val;
    ngx_str_t content_type;

    type_val = cfml_eval_tag_attribute(ctx, node, "type");
    if (type_val != NULL) {
        cfml_value_to_string(ctx, type_val, &content_type);
        ctx->r->headers_out.content_type = content_type;
        ctx->r->headers_out.content_type_len = content_type.len;
    }

    /* Check for reset attribute */
    if (cfml_has_tag_attribute(node, "reset")) {
        /* Clear output buffer */
        ctx->output_chain = NULL;
        ctx->output_last = &ctx->output_chain;
        ctx->output_size = 0;
    }

    return NGX_OK;
}

/* cfcookie */
ngx_int_t
cfml_tag_cookie(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *name;
    cfml_value_t *value_val;
    ngx_str_t value;
    ngx_table_elt_t *cookie;
    u_char *p;
    size_t len;

    name = cfml_get_tag_attribute(node, "name");
    if (name == NULL) {
        ngx_str_set(&ctx->error_message, "cfcookie requires name attribute");
        return NGX_ERROR;
    }

    value_val = cfml_eval_tag_attribute(ctx, node, "value");
    if (value_val != NULL) {
        cfml_value_to_string(ctx, value_val, &value);
    } else {
        ngx_str_set(&value, "");
    }

    cookie = ngx_list_push(&ctx->r->headers_out.headers);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    cookie->hash = 1;
    ngx_str_set(&cookie->key, "Set-Cookie");

    /* Build cookie value */
    len = name->len + 1 + value.len + 64;  /* Extra space for attributes */
    cookie->value.data = ngx_pnalloc(ctx->pool, len);
    if (cookie->value.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(cookie->value.data, "%V=%V", name, &value);

    /* Add path if specified */
    ngx_str_t *path = cfml_get_tag_attribute(node, "path");
    if (path != NULL) {
        p = ngx_sprintf(p, "; Path=%V", path);
    }

    /* Add expires if specified */
    cfml_value_t *expires_val = cfml_eval_tag_attribute(ctx, node, "expires");
    if (expires_val != NULL) {
        /* Handle expires */
    }

    /* Add secure flag */
    if (cfml_has_tag_attribute(node, "secure")) {
        p = ngx_sprintf(p, "; Secure");
    }

    /* Add httponly flag */
    if (cfml_has_tag_attribute(node, "httponly")) {
        p = ngx_sprintf(p, "; HttpOnly");
    }

    cookie->value.len = p - cookie->value.data;

    return NGX_OK;
}

/* cfsavecontent */
ngx_int_t
cfml_tag_savecontent(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_str_t *var_name;
    ngx_chain_t *saved_chain;
    ngx_chain_t **saved_last;
    size_t saved_size;
    ngx_str_t content;
    ngx_chain_t *cl;
    u_char *p;

    var_name = cfml_get_tag_attribute(node, "variable");
    if (var_name == NULL) {
        ngx_str_set(&ctx->error_message, "cfsavecontent requires variable attribute");
        return NGX_ERROR;
    }

    /* Save current output state */
    saved_chain = ctx->output_chain;
    saved_last = ctx->output_last;
    saved_size = ctx->output_size;

    /* Reset output */
    ctx->output_chain = NULL;
    ctx->output_last = &ctx->output_chain;
    ctx->output_size = 0;

    /* Execute body */
    ngx_int_t rc = cfml_execute_children(ctx, node);

    /* Capture output */
    content.len = ctx->output_size;
    content.data = ngx_pnalloc(ctx->pool, content.len + 1);
    if (content.data == NULL) {
        return NGX_ERROR;
    }

    p = content.data;
    for (cl = ctx->output_chain; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }
    *p = '\0';

    /* Set variable */
    cfml_set_variable(ctx, var_name, cfml_create_string(ctx->pool, &content));

    /* Restore output state */
    ctx->output_chain = saved_chain;
    ctx->output_last = saved_last;
    ctx->output_size = saved_size;

    return rc;
}

/* cfsilent */
ngx_int_t
cfml_tag_silent(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    ngx_chain_t *saved_chain;
    ngx_chain_t **saved_last;
    size_t saved_size;

    /* Save current output state */
    saved_chain = ctx->output_chain;
    saved_last = ctx->output_last;
    saved_size = ctx->output_size;

    /* Reset output (discard) */
    ctx->output_chain = NULL;
    ctx->output_last = &ctx->output_chain;
    ctx->output_size = 0;

    /* Execute body */
    ngx_int_t rc = cfml_execute_children(ctx, node);

    /* Restore output state (discard captured output) */
    ctx->output_chain = saved_chain;
    ctx->output_last = saved_last;
    ctx->output_size = saved_size;

    return rc;
}

/* cfflush */
ngx_int_t
cfml_tag_flush(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    /* Flush is a no-op in this implementation since we buffer everything */
    return NGX_OK;
}

/* cfsetting */
ngx_int_t
cfml_tag_setting(cfml_context_t *ctx, cfml_ast_node_t *node)
{
    cfml_value_t *val;

    /* enablecfoutputonly */
    val = cfml_eval_tag_attribute(ctx, node, "enablecfoutputonly");
    if (val != NULL) {
        ctx->enable_cfoutput_only = cfml_value_to_boolean(val);
    }

    /* requesttimeout */
    val = cfml_eval_tag_attribute(ctx, node, "requesttimeout");
    if (val != NULL) {
        int64_t timeout;
        cfml_value_to_integer(val, &timeout);
        ctx->request_timeout = (ngx_uint_t)timeout;
    }

    /* showdebugoutput */
    val = cfml_eval_tag_attribute(ctx, node, "showdebugoutput");
    if (val != NULL) {
        ctx->debug = cfml_value_to_boolean(val);
    }

    return NGX_OK;
}

/* Stub implementations for complex tags */
ngx_int_t cfml_tag_component(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_property(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_invoke(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_invokeargument(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_query(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_queryparam(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_storedproc(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_procparam(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_procresult(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_transaction(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_http(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_httpparam(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_switch(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_case(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_defaultcase(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_try(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_catch(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_finally(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_throw(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_rethrow(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_file(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_directory(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_mail(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_mailparam(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_mailpart(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_lock(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_thread(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_cache(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_schedule(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_script(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }
ngx_int_t cfml_tag_module(cfml_context_t *ctx, cfml_ast_node_t *node) { return NGX_OK; }

/* Dump value for cfdump */
ngx_int_t
cfml_dump_value(cfml_context_t *ctx, cfml_value_t *value, ngx_str_t *output)
{
    u_char *p;
    size_t len = 1024;  /* Initial buffer size */

    output->data = ngx_pnalloc(ctx->pool, len);
    if (output->data == NULL) {
        return NGX_ERROR;
    }

    p = output->data;

    if (value == NULL || value->is_null) {
        p = ngx_sprintf(p, "[null]");
    } else {
        switch (value->type) {
        case CFML_TYPE_STRING:
            p = ngx_sprintf(p, "[string] \"%V\"", &value->data.string);
            break;
        case CFML_TYPE_INTEGER:
            p = ngx_sprintf(p, "[number] %L", value->data.integer);
            break;
        case CFML_TYPE_FLOAT:
            p = ngx_sprintf(p, "[number] %f", value->data.floating);
            break;
        case CFML_TYPE_BOOLEAN:
            p = ngx_sprintf(p, "[boolean] %s", 
                            value->data.boolean ? "true" : "false");
            break;
        case CFML_TYPE_ARRAY:
            p = ngx_sprintf(p, "[array] (%uz elements)", 
                            cfml_array_len(value->data.array));
            break;
        case CFML_TYPE_STRUCT:
            p = ngx_sprintf(p, "[struct] (%uz keys)",
                            cfml_struct_count(value->data.structure));
            break;
        case CFML_TYPE_QUERY:
            p = ngx_sprintf(p, "[query] (%uz rows)",
                            cfml_query_row_count(value->data.query));
            break;
        case CFML_TYPE_DATE:
            p = ngx_sprintf(p, "[date] %T", value->data.date.time);
            break;
        case CFML_TYPE_COMPONENT:
            p = ngx_sprintf(p, "[component]");
            break;
        default:
            p = ngx_sprintf(p, "[unknown type]");
            break;
        }
    }

    output->len = p - output->data;
    return NGX_OK;
}
