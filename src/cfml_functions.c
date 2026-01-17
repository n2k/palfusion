/*
 * CFML Built-in Functions - Implementation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>
#include <time.h>
#include "cfml_functions.h"
#include "cfml_variables.h"
#include "cfml_runtime.h"
#include "cfml_hash.h"
#include "cfml_json.h"

/* Built-in function definitions */
static cfml_builtin_def_t cfml_builtins[] = {
    /* String functions */
    { ngx_string("len"), cfml_func_len, 1, 1, ngx_string("Returns string length") },
    { ngx_string("trim"), cfml_func_trim, 1, 1, ngx_string("Trims whitespace") },
    { ngx_string("ltrim"), cfml_func_ltrim, 1, 1, ngx_string("Left trim") },
    { ngx_string("rtrim"), cfml_func_rtrim, 1, 1, ngx_string("Right trim") },
    { ngx_string("ucase"), cfml_func_ucase, 1, 1, ngx_string("Uppercase") },
    { ngx_string("lcase"), cfml_func_lcase, 1, 1, ngx_string("Lowercase") },
    { ngx_string("left"), cfml_func_left, 2, 2, ngx_string("Left substring") },
    { ngx_string("right"), cfml_func_right, 2, 2, ngx_string("Right substring") },
    { ngx_string("mid"), cfml_func_mid, 2, 3, ngx_string("Middle substring") },
    { ngx_string("find"), cfml_func_find, 2, 3, ngx_string("Find substring") },
    { ngx_string("findnocase"), cfml_func_findnocase, 2, 3, ngx_string("Find case-insensitive") },
    { ngx_string("replace"), cfml_func_replace, 3, 4, ngx_string("Replace substring") },
    { ngx_string("reverse"), cfml_func_reverse, 1, 1, ngx_string("Reverse string") },
    { ngx_string("repeatstring"), cfml_func_repeatstring, 2, 2, ngx_string("Repeat string") },
    { ngx_string("asc"), cfml_func_asc, 1, 1, ngx_string("ASCII value") },
    { ngx_string("chr"), cfml_func_chr, 1, 1, ngx_string("Character from ASCII") },
    
    /* List functions */
    { ngx_string("listlen"), cfml_func_listlen, 1, 2, ngx_string("List length") },
    { ngx_string("listgetat"), cfml_func_listgetat, 2, 3, ngx_string("Get list element") },
    { ngx_string("listappend"), cfml_func_listappend, 2, 3, ngx_string("Append to list") },
    { ngx_string("listprepend"), cfml_func_listprepend, 2, 3, ngx_string("Prepend to list") },
    { ngx_string("listfind"), cfml_func_listfind, 2, 3, ngx_string("Find in list") },
    { ngx_string("listcontains"), cfml_func_listcontains, 2, 3, ngx_string("List contains") },
    { ngx_string("listtoarray"), cfml_func_listtoarray, 1, 2, ngx_string("List to array") },
    { ngx_string("listsort"), cfml_func_listsort, 2, 3, ngx_string("Sort list") },
    
    /* Numeric functions */
    { ngx_string("abs"), cfml_func_abs, 1, 1, ngx_string("Absolute value") },
    { ngx_string("ceiling"), cfml_func_ceiling, 1, 1, ngx_string("Ceiling") },
    { ngx_string("floor"), cfml_func_floor, 1, 1, ngx_string("Floor") },
    { ngx_string("round"), cfml_func_round, 1, 2, ngx_string("Round") },
    { ngx_string("int"), cfml_func_int, 1, 1, ngx_string("Integer part") },
    { ngx_string("fix"), cfml_func_fix, 1, 1, ngx_string("Fix") },
    { ngx_string("sgn"), cfml_func_sgn, 1, 1, ngx_string("Sign") },
    { ngx_string("max"), cfml_func_max, 2, 2, ngx_string("Maximum") },
    { ngx_string("min"), cfml_func_min, 2, 2, ngx_string("Minimum") },
    { ngx_string("rand"), cfml_func_rand, 0, 1, ngx_string("Random number") },
    { ngx_string("randrange"), cfml_func_randrange, 2, 3, ngx_string("Random in range") },
    { ngx_string("sqr"), cfml_func_sqr, 1, 1, ngx_string("Square root") },
    { ngx_string("log"), cfml_func_log, 1, 1, ngx_string("Natural log") },
    { ngx_string("log10"), cfml_func_log10, 1, 1, ngx_string("Log base 10") },
    { ngx_string("exp"), cfml_func_exp, 1, 1, ngx_string("Exponential") },
    { ngx_string("pow"), cfml_func_pow, 2, 2, ngx_string("Power") },
    { ngx_string("sin"), cfml_func_sin, 1, 1, ngx_string("Sine") },
    { ngx_string("cos"), cfml_func_cos, 1, 1, ngx_string("Cosine") },
    { ngx_string("tan"), cfml_func_tan, 1, 1, ngx_string("Tangent") },
    { ngx_string("pi"), cfml_func_pi, 0, 0, ngx_string("Pi constant") },
    
    /* Date/Time functions */
    { ngx_string("now"), cfml_func_now, 0, 0, ngx_string("Current date/time") },
    { ngx_string("dateformat"), cfml_func_dateformat, 1, 2, ngx_string("Format date") },
    { ngx_string("timeformat"), cfml_func_timeformat, 1, 2, ngx_string("Format time") },
    { ngx_string("createdate"), cfml_func_createdate, 3, 3, ngx_string("Create date") },
    { ngx_string("createdatetime"), cfml_func_createdatetime, 6, 6, ngx_string("Create datetime") },
    { ngx_string("year"), cfml_func_year, 1, 1, ngx_string("Year component") },
    { ngx_string("month"), cfml_func_month, 1, 1, ngx_string("Month component") },
    { ngx_string("day"), cfml_func_day, 1, 1, ngx_string("Day component") },
    { ngx_string("hour"), cfml_func_hour, 1, 1, ngx_string("Hour component") },
    { ngx_string("minute"), cfml_func_minute, 1, 1, ngx_string("Minute component") },
    { ngx_string("second"), cfml_func_second, 1, 1, ngx_string("Second component") },
    { ngx_string("dayofweek"), cfml_func_dayofweek, 1, 1, ngx_string("Day of week") },
    { ngx_string("dayofyear"), cfml_func_dayofyear, 1, 1, ngx_string("Day of year") },
    { ngx_string("isdate"), cfml_func_isdate, 1, 1, ngx_string("Is valid date") },
    { ngx_string("dateadd"), cfml_func_dateadd, 3, 3, ngx_string("Add to date") },
    { ngx_string("datediff"), cfml_func_datediff, 3, 3, ngx_string("Date difference") },
    { ngx_string("createtimespan"), cfml_func_createtimespan, 4, 4, ngx_string("Create timespan") },
    
    /* Array functions */
    { ngx_string("arraynew"), cfml_func_arraynew, 0, 1, ngx_string("Create array") },
    { ngx_string("arraylen"), cfml_func_arraylen, 1, 1, ngx_string("Array length") },
    { ngx_string("arrayappend"), cfml_func_arrayappend, 2, 2, ngx_string("Append to array") },
    { ngx_string("arrayprepend"), cfml_func_arrayprepend, 2, 2, ngx_string("Prepend to array") },
    { ngx_string("arraydeleteat"), cfml_func_arraydeleteat, 2, 2, ngx_string("Delete from array") },
    { ngx_string("arrayinsertat"), cfml_func_arrayinsertat, 3, 3, ngx_string("Insert in array") },
    { ngx_string("arraysort"), cfml_func_arraysort, 2, 3, ngx_string("Sort array") },
    { ngx_string("arraytolist"), cfml_func_arraytolist, 1, 2, ngx_string("Array to list") },
    { ngx_string("arrayfind"), cfml_func_arrayfind, 2, 2, ngx_string("Find in array") },
    { ngx_string("arraycontains"), cfml_func_arraycontains, 2, 2, ngx_string("Array contains") },
    { ngx_string("arrayclear"), cfml_func_arrayclear, 1, 1, ngx_string("Clear array") },
    { ngx_string("arrayisempty"), cfml_func_arrayisempty, 1, 1, ngx_string("Is array empty") },
    
    /* Struct functions */
    { ngx_string("structnew"), cfml_func_structnew, 0, 0, ngx_string("Create struct") },
    { ngx_string("structkeyexists"), cfml_func_structkeyexists, 2, 2, ngx_string("Key exists") },
    { ngx_string("structkeylist"), cfml_func_structkeylist, 1, 2, ngx_string("List keys") },
    { ngx_string("structcount"), cfml_func_structcount, 1, 1, ngx_string("Key count") },
    { ngx_string("structdelete"), cfml_func_structdelete, 2, 2, ngx_string("Delete key") },
    { ngx_string("structclear"), cfml_func_structclear, 1, 1, ngx_string("Clear struct") },
    { ngx_string("structcopy"), cfml_func_structcopy, 1, 1, ngx_string("Copy struct") },
    { ngx_string("structisempty"), cfml_func_structisempty, 1, 1, ngx_string("Is struct empty") },
    
    /* Query functions */
    { ngx_string("querynew"), cfml_func_querynew, 1, 2, ngx_string("Create query") },
    { ngx_string("queryaddrow"), cfml_func_queryaddrow, 1, 2, ngx_string("Add row") },
    { ngx_string("querysetcell"), cfml_func_querysetcell, 3, 4, ngx_string("Set cell") },
    { ngx_string("queryaddcolumn"), cfml_func_queryaddcolumn, 2, 3, ngx_string("Add column") },
    
    /* Decision functions */
    { ngx_string("isdefined"), cfml_func_isdefined, 1, 1, ngx_string("Is defined") },
    { ngx_string("isnumeric"), cfml_func_isnumeric, 1, 1, ngx_string("Is numeric") },
    { ngx_string("isarray"), cfml_func_isarray, 1, 1, ngx_string("Is array") },
    { ngx_string("isstruct"), cfml_func_isstruct, 1, 1, ngx_string("Is struct") },
    { ngx_string("isquery"), cfml_func_isquery, 1, 1, ngx_string("Is query") },
    { ngx_string("issimplevalue"), cfml_func_issimplevalue, 1, 1, ngx_string("Is simple") },
    { ngx_string("isboolean"), cfml_func_isboolean, 1, 1, ngx_string("Is boolean") },
    { ngx_string("isnull"), cfml_func_isnull, 1, 1, ngx_string("Is null") },
    { ngx_string("isempty"), cfml_func_isempty, 1, 1, ngx_string("Is empty") },
    { ngx_string("isjson"), cfml_func_isjson, 1, 1, ngx_string("Is JSON") },
    
    /* Conversion functions */
    { ngx_string("tostring"), cfml_func_tostring, 1, 1, ngx_string("Convert to string") },
    { ngx_string("val"), cfml_func_val, 1, 1, ngx_string("Numeric value") },
    { ngx_string("numberformat"), cfml_func_numberformat, 1, 2, ngx_string("Format number") },
    { ngx_string("yesnoformat"), cfml_func_yesnoformat, 1, 1, ngx_string("Yes/No format") },
    
    /* Encoding functions */
    { ngx_string("urlencodedformat"), cfml_func_urlencodedformat, 1, 1, ngx_string("URL encode") },
    { ngx_string("urldecode"), cfml_func_urldecode, 1, 1, ngx_string("URL decode") },
    { ngx_string("htmleditformat"), cfml_func_htmleditformat, 1, 1, ngx_string("HTML encode") },
    { ngx_string("htmlcodeformat"), cfml_func_htmlcodeformat, 1, 1, ngx_string("HTML code format") },
    { ngx_string("jsstringformat"), cfml_func_jsstringformat, 1, 1, ngx_string("JS escape") },
    { ngx_string("serializejson"), cfml_func_serializejson, 1, 4, ngx_string("Serialize JSON") },
    { ngx_string("deserializejson"), cfml_func_deserializejson, 1, 3, ngx_string("Deserialize JSON") },
    { ngx_string("jsonparse"), cfml_func_jsonparse, 1, 1, ngx_string("Parse JSON") },
    { ngx_string("jsonserialize"), cfml_func_jsonserialize, 1, 1, ngx_string("Serialize to JSON") },
    { ngx_string("hash"), cfml_func_hash, 1, 3, ngx_string("Hash string") },
    { ngx_string("tobase64"), cfml_func_tobase64, 1, 2, ngx_string("Base64 encode") },
    
    /* Other functions */
    { ngx_string("writeoutput"), cfml_func_writeoutput, 1, 1, ngx_string("Write output") },
    { ngx_string("gettickcount"), cfml_func_gettickcount, 0, 0, ngx_string("Tick count") },
    { ngx_string("sleep"), cfml_func_sleep, 1, 1, ngx_string("Sleep") },
    { ngx_string("createuuid"), cfml_func_createuuid, 0, 0, ngx_string("Create UUID") },
    { ngx_string("duplicate"), cfml_func_duplicate, 1, 1, ngx_string("Duplicate value") },
    
    { ngx_null_string, NULL, 0, 0, ngx_null_string }
};

/* Hash table for quick lookup */
static ngx_hash_t cfml_builtin_hash;

/* Initialize built-in functions */
ngx_int_t
cfml_init_builtin_functions(ngx_conf_t *cf, ngx_hash_t *hash)
{
    ngx_hash_init_t hash_init;
    ngx_array_t keys;
    ngx_hash_key_t *hk;
    cfml_builtin_def_t *def;

    if (ngx_array_init(&keys, cf->pool, 128, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    for (def = cfml_builtins; def->name.len > 0; def++) {
        hk = ngx_array_push(&keys);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = def->name;
        hk->key_hash = ngx_hash_key_lc(def->name.data, def->name.len);
        hk->value = def;
    }

    hash_init.hash = hash;
    hash_init.key = ngx_hash_key_lc;
    hash_init.max_size = 512;
    hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash_init.name = "cfml_builtins";
    hash_init.pool = cf->pool;
    hash_init.temp_pool = cf->temp_pool;

    if (ngx_hash_init(&hash_init, keys.elts, keys.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    cfml_builtin_hash = *hash;

    return NGX_OK;
}

/* Check if function is built-in */
ngx_int_t
cfml_is_builtin_function(ngx_str_t *name)
{
    u_char lc_name[256];
    size_t len = name->len > 255 ? 255 : name->len;
    ngx_uint_t i;

    for (i = 0; i < len; i++) {
        lc_name[i] = ngx_tolower(name->data[i]);
    }

    return ngx_hash_find(&cfml_builtin_hash, ngx_hash_key_lc(lc_name, len),
                         lc_name, len) != NULL;
}

/* Get built-in function definition */
cfml_builtin_def_t *
cfml_get_builtin_def(ngx_str_t *name)
{
    u_char lc_name[256];
    size_t len = name->len > 255 ? 255 : name->len;
    ngx_uint_t i;

    for (i = 0; i < len; i++) {
        lc_name[i] = ngx_tolower(name->data[i]);
    }

    return ngx_hash_find(&cfml_builtin_hash, ngx_hash_key_lc(lc_name, len),
                         lc_name, len);
}

/* Call built-in function */
cfml_value_t *
cfml_call_builtin(cfml_context_t *ctx, ngx_str_t *name, ngx_array_t *args)
{
    cfml_builtin_def_t *def;

    def = cfml_get_builtin_def(name);
    if (def == NULL) {
        return cfml_create_null(ctx->pool);
    }

    /* Validate argument count */
    if ((ngx_int_t)args->nelts < def->min_args) {
        ngx_str_set(&ctx->error_message, "Too few arguments");
        return cfml_create_null(ctx->pool);
    }

    if (def->max_args >= 0 && (ngx_int_t)args->nelts > def->max_args) {
        ngx_str_set(&ctx->error_message, "Too many arguments");
        return cfml_create_null(ctx->pool);
    }

    return def->handler(ctx, args);
}

/* Helper: Get argument */
static cfml_value_t *
get_arg(ngx_array_t *args, ngx_uint_t index)
{
    cfml_value_t **items;
    if (index >= args->nelts) {
        return NULL;
    }
    items = args->elts;
    return items[index];
}

/* ===== String Functions ===== */

cfml_value_t *cfml_func_len(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str;
    
    if (val->type == CFML_TYPE_ARRAY) {
        return cfml_create_integer(ctx->pool, cfml_array_len(val->data.array));
    }
    if (val->type == CFML_TYPE_STRUCT) {
        return cfml_create_integer(ctx->pool, cfml_struct_count(val->data.structure));
    }
    
    cfml_value_to_string(ctx, val, &str);
    return cfml_create_integer(ctx->pool, str.len);
}

cfml_value_t *cfml_func_trim(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    u_char *p, *end;
    
    cfml_value_to_string(ctx, val, &str);
    
    p = str.data;
    end = str.data + str.len;
    
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
        p++;
    }
    
    while (end > p && (*(end-1) == ' ' || *(end-1) == '\t' || 
                       *(end-1) == '\n' || *(end-1) == '\r')) {
        end--;
    }
    
    result.data = p;
    result.len = end - p;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_ltrim(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    u_char *p, *end;
    
    cfml_value_to_string(ctx, val, &str);
    
    p = str.data;
    end = str.data + str.len;
    
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
        p++;
    }
    
    result.data = p;
    result.len = end - p;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_rtrim(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    u_char *end;
    
    cfml_value_to_string(ctx, val, &str);
    
    end = str.data + str.len;
    
    while (end > str.data && (*(end-1) == ' ' || *(end-1) == '\t' ||
                              *(end-1) == '\n' || *(end-1) == '\r')) {
        end--;
    }
    
    result.data = str.data;
    result.len = end - str.data;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_ucase(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    ngx_uint_t i;
    
    cfml_value_to_string(ctx, val, &str);
    
    result.len = str.len;
    result.data = ngx_pnalloc(ctx->pool, str.len + 1);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    for (i = 0; i < str.len; i++) {
        result.data[i] = ngx_toupper(str.data[i]);
    }
    result.data[str.len] = '\0';
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_lcase(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    ngx_uint_t i;
    
    cfml_value_to_string(ctx, val, &str);
    
    result.len = str.len;
    result.data = ngx_pnalloc(ctx->pool, str.len + 1);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    for (i = 0; i < str.len; i++) {
        result.data[i] = ngx_tolower(str.data[i]);
    }
    result.data[str.len] = '\0';
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_left(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *str_val = get_arg(args, 0);
    cfml_value_t *count_val = get_arg(args, 1);
    ngx_str_t str, result;
    int64_t count;
    
    cfml_value_to_string(ctx, str_val, &str);
    cfml_value_to_integer(count_val, &count);
    
    if (count < 0) count = 0;
    if ((size_t)count > str.len) count = str.len;
    
    result.data = str.data;
    result.len = count;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_right(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *str_val = get_arg(args, 0);
    cfml_value_t *count_val = get_arg(args, 1);
    ngx_str_t str, result;
    int64_t count;
    
    cfml_value_to_string(ctx, str_val, &str);
    cfml_value_to_integer(count_val, &count);
    
    if (count < 0) count = 0;
    if ((size_t)count > str.len) count = str.len;
    
    result.data = str.data + str.len - count;
    result.len = count;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_mid(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *str_val = get_arg(args, 0);
    cfml_value_t *start_val = get_arg(args, 1);
    cfml_value_t *count_val = args->nelts > 2 ? get_arg(args, 2) : NULL;
    ngx_str_t str, result;
    int64_t start, count;
    
    cfml_value_to_string(ctx, str_val, &str);
    cfml_value_to_integer(start_val, &start);
    
    start--;  /* CFML is 1-indexed */
    if (start < 0) start = 0;
    if ((size_t)start >= str.len) {
        ngx_str_set(&result, "");
        return cfml_create_string(ctx->pool, &result);
    }
    
    if (count_val != NULL) {
        cfml_value_to_integer(count_val, &count);
    } else {
        count = str.len - start;
    }
    
    if (count < 0) count = 0;
    if (start + count > (int64_t)str.len) count = str.len - start;
    
    result.data = str.data + start;
    result.len = count;
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_find(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *substr_val = get_arg(args, 0);
    cfml_value_t *str_val = get_arg(args, 1);
    cfml_value_t *start_val = args->nelts > 2 ? get_arg(args, 2) : NULL;
    ngx_str_t str, substr;
    int64_t start = 1;
    u_char *p;
    
    cfml_value_to_string(ctx, substr_val, &substr);
    cfml_value_to_string(ctx, str_val, &str);
    
    if (start_val != NULL) {
        cfml_value_to_integer(start_val, &start);
    }
    
    start--;
    if (start < 0) start = 0;
    if ((size_t)start >= str.len || substr.len == 0) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    p = str.data + start;
    while (p + substr.len <= str.data + str.len) {
        if (ngx_memcmp(p, substr.data, substr.len) == 0) {
            return cfml_create_integer(ctx->pool, (p - str.data) + 1);
        }
        p++;
    }
    
    return cfml_create_integer(ctx->pool, 0);
}

cfml_value_t *cfml_func_findnocase(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *substr_val = get_arg(args, 0);
    cfml_value_t *str_val = get_arg(args, 1);
    cfml_value_t *start_val = args->nelts > 2 ? get_arg(args, 2) : NULL;
    ngx_str_t str, substr;
    int64_t start = 1;
    u_char *p;
    
    cfml_value_to_string(ctx, substr_val, &substr);
    cfml_value_to_string(ctx, str_val, &str);
    
    if (start_val != NULL) {
        cfml_value_to_integer(start_val, &start);
    }
    
    start--;
    if (start < 0) start = 0;
    if ((size_t)start >= str.len || substr.len == 0) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    p = str.data + start;
    while (p + substr.len <= str.data + str.len) {
        if (ngx_strncasecmp(p, substr.data, substr.len) == 0) {
            return cfml_create_integer(ctx->pool, (p - str.data) + 1);
        }
        p++;
    }
    
    return cfml_create_integer(ctx->pool, 0);
}

cfml_value_t *cfml_func_replace(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *str_val = get_arg(args, 0);
    cfml_value_t *substr_val = get_arg(args, 1);
    cfml_value_t *repl_val = get_arg(args, 2);
    ngx_str_t str, substr, repl, result;
    u_char *p, *out;
    
    cfml_value_to_string(ctx, str_val, &str);
    cfml_value_to_string(ctx, substr_val, &substr);
    cfml_value_to_string(ctx, repl_val, &repl);
    
    if (substr.len == 0) {
        return cfml_create_string(ctx->pool, &str);
    }
    
    /* Simple single replacement */
    p = str.data;
    while (p + substr.len <= str.data + str.len) {
        if (ngx_memcmp(p, substr.data, substr.len) == 0) {
            result.len = str.len - substr.len + repl.len;
            result.data = ngx_pnalloc(ctx->pool, result.len + 1);
            if (result.data == NULL) {
                return cfml_create_null(ctx->pool);
            }
            
            out = ngx_copy(result.data, str.data, p - str.data);
            out = ngx_copy(out, repl.data, repl.len);
            out = ngx_copy(out, p + substr.len, 
                          str.len - (p - str.data) - substr.len);
            *out = '\0';
            
            return cfml_create_string(ctx->pool, &result);
        }
        p++;
    }
    
    return cfml_create_string(ctx->pool, &str);
}

cfml_value_t *cfml_func_reverse(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    ngx_uint_t i;
    
    cfml_value_to_string(ctx, val, &str);
    
    result.len = str.len;
    result.data = ngx_pnalloc(ctx->pool, str.len + 1);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    for (i = 0; i < str.len; i++) {
        result.data[i] = str.data[str.len - 1 - i];
    }
    result.data[str.len] = '\0';
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_repeatstring(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *str_val = get_arg(args, 0);
    cfml_value_t *count_val = get_arg(args, 1);
    ngx_str_t str, result;
    int64_t count;
    u_char *p;
    
    cfml_value_to_string(ctx, str_val, &str);
    cfml_value_to_integer(count_val, &count);
    
    if (count <= 0) {
        ngx_str_set(&result, "");
        return cfml_create_string(ctx->pool, &result);
    }
    
    result.len = str.len * count;
    result.data = ngx_pnalloc(ctx->pool, result.len + 1);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    
    p = result.data;
    while (count-- > 0) {
        p = ngx_copy(p, str.data, str.len);
    }
    *p = '\0';
    
    return cfml_create_string(ctx->pool, &result);
}

cfml_value_t *cfml_func_asc(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str;
    
    cfml_value_to_string(ctx, val, &str);
    
    if (str.len == 0) {
        return cfml_create_integer(ctx->pool, 0);
    }
    
    return cfml_create_integer(ctx->pool, str.data[0]);
}

cfml_value_t *cfml_func_chr(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    int64_t code;
    ngx_str_t result;
    
    cfml_value_to_integer(val, &code);
    
    result.len = 1;
    result.data = ngx_pnalloc(ctx->pool, 2);
    if (result.data == NULL) {
        return cfml_create_null(ctx->pool);
    }
    result.data[0] = (u_char)code;
    result.data[1] = '\0';
    
    return cfml_create_string(ctx->pool, &result);
}

/* ===== Numeric Functions ===== */

cfml_value_t *cfml_func_abs(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, fabs(num));
}

cfml_value_t *cfml_func_ceiling(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_integer(ctx->pool, (int64_t)ceil(num));
}

cfml_value_t *cfml_func_floor(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_integer(ctx->pool, (int64_t)floor(num));
}

cfml_value_t *cfml_func_round(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    cfml_value_t *precision_val = args->nelts > 1 ? get_arg(args, 1) : NULL;
    double num;
    int64_t precision = 0;
    
    cfml_value_to_float(val, &num);
    
    if (precision_val != NULL) {
        cfml_value_to_integer(precision_val, &precision);
    }
    
    if (precision == 0) {
        return cfml_create_integer(ctx->pool, (int64_t)round(num));
    }
    
    double mult = pow(10, precision);
    return cfml_create_float(ctx->pool, round(num * mult) / mult);
}

cfml_value_t *cfml_func_int(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_integer(ctx->pool, (int64_t)num);
}

cfml_value_t *cfml_func_fix(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_integer(ctx->pool, (int64_t)trunc(num));
}

cfml_value_t *cfml_func_sgn(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    
    if (num < 0) return cfml_create_integer(ctx->pool, -1);
    if (num > 0) return cfml_create_integer(ctx->pool, 1);
    return cfml_create_integer(ctx->pool, 0);
}

cfml_value_t *cfml_func_max(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *a = get_arg(args, 0);
    cfml_value_t *b = get_arg(args, 1);
    double na, nb;
    
    cfml_value_to_float(a, &na);
    cfml_value_to_float(b, &nb);
    
    return cfml_create_float(ctx->pool, na > nb ? na : nb);
}

cfml_value_t *cfml_func_min(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *a = get_arg(args, 0);
    cfml_value_t *b = get_arg(args, 1);
    double na, nb;
    
    cfml_value_to_float(a, &na);
    cfml_value_to_float(b, &nb);
    
    return cfml_create_float(ctx->pool, na < nb ? na : nb);
}

cfml_value_t *cfml_func_rand(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_create_float(ctx->pool, (double)rand() / RAND_MAX);
}

cfml_value_t *cfml_func_randrange(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *min_val = get_arg(args, 0);
    cfml_value_t *max_val = get_arg(args, 1);
    int64_t min, max;
    
    cfml_value_to_integer(min_val, &min);
    cfml_value_to_integer(max_val, &max);
    
    if (min > max) {
        int64_t tmp = min;
        min = max;
        max = tmp;
    }
    
    return cfml_create_integer(ctx->pool, min + (rand() % (max - min + 1)));
}

cfml_value_t *cfml_func_sqr(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, sqrt(num));
}

cfml_value_t *cfml_func_log(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, log(num));
}

cfml_value_t *cfml_func_log10(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, log10(num));
}

cfml_value_t *cfml_func_exp(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, exp(num));
}

cfml_value_t *cfml_func_pow(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *base_val = get_arg(args, 0);
    cfml_value_t *exp_val = get_arg(args, 1);
    double base, exponent;
    
    cfml_value_to_float(base_val, &base);
    cfml_value_to_float(exp_val, &exponent);
    
    return cfml_create_float(ctx->pool, pow(base, exponent));
}

cfml_value_t *cfml_func_sin(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, sin(num));
}

cfml_value_t *cfml_func_cos(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, cos(num));
}

cfml_value_t *cfml_func_tan(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    double num;
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, tan(num));
}

cfml_value_t *cfml_func_pi(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_create_float(ctx->pool, 3.14159265358979323846);
}

/* ===== Date/Time Functions ===== */

cfml_value_t *cfml_func_now(cfml_context_t *ctx, ngx_array_t *args)
{
    return cfml_create_date(ctx->pool, time(NULL));
}

cfml_value_t *cfml_func_year(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_year + 1900);
}

cfml_value_t *cfml_func_month(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_mon + 1);
}

cfml_value_t *cfml_func_day(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_mday);
}

cfml_value_t *cfml_func_hour(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_hour);
}

cfml_value_t *cfml_func_minute(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_min);
}

cfml_value_t *cfml_func_second(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_sec);
}

cfml_value_t *cfml_func_dayofweek(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_wday + 1);
}

cfml_value_t *cfml_func_dayofyear(cfml_context_t *ctx, ngx_array_t *args)
{
    cfml_value_t *val = get_arg(args, 0);
    time_t t;
    struct tm *tm;
    
    if (val->type == CFML_TYPE_DATE) {
        t = val->data.date.time;
    } else {
        t = time(NULL);
    }
    
    tm = localtime(&t);
    return cfml_create_integer(ctx->pool, tm->tm_yday + 1);
}

/* Decision functions and remaining stubs */
cfml_value_t *cfml_func_isdate(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, val->type == CFML_TYPE_DATE);
}

cfml_value_t *cfml_func_isdefined(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t name;
    cfml_value_to_string(ctx, val, &name);
    cfml_value_t *var = cfml_get_variable(ctx, &name);
    return cfml_create_boolean(ctx->pool, var != NULL && !var->is_null);
}

cfml_value_t *cfml_func_isnumeric(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, 
        val->type == CFML_TYPE_INTEGER || val->type == CFML_TYPE_FLOAT);
}

cfml_value_t *cfml_func_isarray(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, val->type == CFML_TYPE_ARRAY);
}

cfml_value_t *cfml_func_isstruct(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, val->type == CFML_TYPE_STRUCT);
}

cfml_value_t *cfml_func_isquery(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, val->type == CFML_TYPE_QUERY);
}

cfml_value_t *cfml_func_issimplevalue(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, 
        val->type == CFML_TYPE_STRING || val->type == CFML_TYPE_INTEGER ||
        val->type == CFML_TYPE_FLOAT || val->type == CFML_TYPE_BOOLEAN ||
        val->type == CFML_TYPE_DATE);
}

cfml_value_t *cfml_func_isboolean(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    if (val->type == CFML_TYPE_BOOLEAN) return cfml_create_boolean(ctx->pool, 1);
    if (val->type == CFML_TYPE_STRING) {
        if (ngx_strncasecmp(val->data.string.data, (u_char*)"true", 4) == 0 ||
            ngx_strncasecmp(val->data.string.data, (u_char*)"false", 5) == 0 ||
            ngx_strncasecmp(val->data.string.data, (u_char*)"yes", 3) == 0 ||
            ngx_strncasecmp(val->data.string.data, (u_char*)"no", 2) == 0) {
            return cfml_create_boolean(ctx->pool, 1);
        }
    }
    return cfml_create_boolean(ctx->pool, 0);
}

cfml_value_t *cfml_func_isnull(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_boolean(ctx->pool, val == NULL || val->is_null);
}

cfml_value_t *cfml_func_isempty(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    if (val == NULL || val->is_null) return cfml_create_boolean(ctx->pool, 1);
    if (val->type == CFML_TYPE_STRING) return cfml_create_boolean(ctx->pool, val->data.string.len == 0);
    if (val->type == CFML_TYPE_ARRAY) return cfml_create_boolean(ctx->pool, cfml_array_len(val->data.array) == 0);
    if (val->type == CFML_TYPE_STRUCT) return cfml_create_boolean(ctx->pool, cfml_struct_count(val->data.structure) == 0);
    return cfml_create_boolean(ctx->pool, 0);
}

/* isjson is implemented in cfml_json.c */

/* Other functions */
cfml_value_t *cfml_func_writeoutput(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    cfml_output_value(ctx, val);
    return cfml_create_string_cstr(ctx->pool, "");
}

cfml_value_t *cfml_func_gettickcount(cfml_context_t *ctx, ngx_array_t *args) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return cfml_create_integer(ctx->pool, ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

cfml_value_t *cfml_func_sleep(cfml_context_t *ctx, ngx_array_t *args) {
    /* Don't actually sleep in nginx - just return */
    return cfml_create_null(ctx->pool);
}

cfml_value_t *cfml_func_createuuid(cfml_context_t *ctx, ngx_array_t *args) {
    ngx_str_t uuid;
    cfml_generate_uuid(ctx->pool, &uuid);
    return cfml_create_string(ctx->pool, &uuid);
}

cfml_value_t *cfml_func_duplicate(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_value_duplicate(ctx->pool, val);
}

/* Stubs for remaining functions */
cfml_value_t *cfml_func_dateformat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_timeformat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_createdate(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_date(ctx->pool, time(NULL)); }
cfml_value_t *cfml_func_createdatetime(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_date(ctx->pool, time(NULL)); }
cfml_value_t *cfml_func_dateadd(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_date(ctx->pool, time(NULL)); }
cfml_value_t *cfml_func_datediff(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_createtimespan(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_float(ctx->pool, 0); }
cfml_value_t *cfml_func_listlen(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_listgetat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_listappend(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_listprepend(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_listfind(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_listcontains(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_listtoarray(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_array(ctx->pool); }
cfml_value_t *cfml_func_listsort(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_arraynew(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_array(ctx->pool); }
cfml_value_t *cfml_func_arraylen(cfml_context_t *ctx, ngx_array_t *args) { 
    cfml_value_t *val = get_arg(args, 0);
    if (val->type != CFML_TYPE_ARRAY) return cfml_create_integer(ctx->pool, 0);
    return cfml_create_integer(ctx->pool, cfml_array_len(val->data.array)); 
}
cfml_value_t *cfml_func_arrayappend(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arrayprepend(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arraydeleteat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arrayinsertat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arraysort(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arraytolist(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_arrayfind(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_arraycontains(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 0); }
cfml_value_t *cfml_func_arrayclear(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_arrayisempty(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_structnew(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_struct(ctx->pool); }
cfml_value_t *cfml_func_structkeyexists(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 0); }
cfml_value_t *cfml_func_structkeylist(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
cfml_value_t *cfml_func_structcount(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 0); }
cfml_value_t *cfml_func_structdelete(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_structclear(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_structcopy(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_struct(ctx->pool); }
cfml_value_t *cfml_func_structisempty(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_querynew(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_query(ctx->pool); }
cfml_value_t *cfml_func_queryaddrow(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 1); }
cfml_value_t *cfml_func_querysetcell(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_boolean(ctx->pool, 1); }
cfml_value_t *cfml_func_queryaddcolumn(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_integer(ctx->pool, 1); }
cfml_value_t *cfml_func_tostring(cfml_context_t *ctx, ngx_array_t *args) { 
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str;
    cfml_value_to_string(ctx, val, &str);
    return cfml_create_string(ctx->pool, &str);
}
cfml_value_t *cfml_func_val(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    double num;
    cfml_value_to_float(val, &num);
    return cfml_create_float(ctx->pool, num);
}
cfml_value_t *cfml_func_numberformat(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, "0"); }
cfml_value_t *cfml_func_yesnoformat(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    return cfml_create_string_cstr(ctx->pool, cfml_value_to_boolean(val) ? "Yes" : "No");
}
cfml_value_t *cfml_func_urlencodedformat(cfml_context_t *ctx, ngx_array_t *args) { return get_arg(args, 0); }
cfml_value_t *cfml_func_urldecode(cfml_context_t *ctx, ngx_array_t *args) { return get_arg(args, 0); }
cfml_value_t *cfml_func_htmleditformat(cfml_context_t *ctx, ngx_array_t *args) { return get_arg(args, 0); }
cfml_value_t *cfml_func_htmlcodeformat(cfml_context_t *ctx, ngx_array_t *args) { return get_arg(args, 0); }
cfml_value_t *cfml_func_jsstringformat(cfml_context_t *ctx, ngx_array_t *args) { return get_arg(args, 0); }
/* JSON functions are implemented in cfml_json.c */
cfml_value_t *cfml_func_hash(cfml_context_t *ctx, ngx_array_t *args) {
    cfml_value_t *val = get_arg(args, 0);
    ngx_str_t str, result;
    cfml_value_to_string(ctx, val, &str);
    cfml_hash_string(ctx->pool, &str, CFML_HASH_MD5, CFML_ENCODING_HEX, &result);
    return cfml_create_string(ctx->pool, &result);
}
cfml_value_t *cfml_func_tobase64(cfml_context_t *ctx, ngx_array_t *args) { return cfml_create_string_cstr(ctx->pool, ""); }
