/*
 * CFML Built-in Functions
 */

#ifndef _CFML_FUNCTIONS_H_
#define _CFML_FUNCTIONS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "cfml_types.h"

/* Initialize built-in functions hash */
ngx_int_t cfml_init_builtin_functions(ngx_conf_t *cf, ngx_hash_t *hash);

/* Call a built-in function */
cfml_value_t *cfml_call_builtin(cfml_context_t *ctx, ngx_str_t *name,
                                ngx_array_t *args);

/* Check if function is built-in */
ngx_int_t cfml_is_builtin_function(ngx_str_t *name);

/* Get function definition */
cfml_builtin_def_t *cfml_get_builtin_def(ngx_str_t *name);

/* ===== String Functions ===== */
cfml_value_t *cfml_func_len(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_trim(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_ltrim(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rtrim(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_ucase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_lcase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_left(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_right(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_mid(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_find(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_findnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_replace(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_replacenocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_replacelist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_reverse(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_repeatstring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_spanincluding(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_spanexcluding(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_insert(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_removechars(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_compare(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_comparenocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_asc(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_chr(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_wrap(cfml_context_t *ctx, ngx_array_t *args);

/* ===== List Functions ===== */
cfml_value_t *cfml_func_listlen(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listgetat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listsetat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listappend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listprepend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listdeleteat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listinsertat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listfind(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listfindnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listcontains(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listcontainsnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listsort(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listchangedelims(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listfirst(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listlast(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listrest(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listtoarray(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listqualify(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_listremoveduplicates(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Regex Functions ===== */
cfml_value_t *cfml_func_refind(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_refindnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rereplace(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rereplacenocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rematch(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rematchnocase(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Numeric Functions ===== */
cfml_value_t *cfml_func_abs(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_ceiling(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_floor(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_round(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_int(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_fix(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_sgn(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_max(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_min(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_rand(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_randrange(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_randomize(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_sqr(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_log(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_log10(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_exp(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_pow(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_mod(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_sin(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_cos(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_tan(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_asin(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_acos(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_atn(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_pi(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_incrementvalue(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_decrementvalue(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Formatting Functions ===== */
cfml_value_t *cfml_func_numberformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_decimalformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dollarformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_percentformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_yesnoformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_booleanformat(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Date/Time Functions ===== */
cfml_value_t *cfml_func_now(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dateformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_timeformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_lsdateformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_lstimeformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createdate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createtime(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createdatetime(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createodbcdate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createodbctime(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createodbcdatetime(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_year(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_month(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_day(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_hour(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_minute(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_second(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_millisecond(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dayofweek(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dayofweekasstring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dayofyear(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_daysinmonth(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_daysinyear(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_firstdayofmonth(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_quarter(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_week(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_monthashortstring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_monthasstring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isleapyear(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isdate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_dateadd(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_datediff(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_datecompare(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_datepart(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_parsedatetime(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gettimezoneinfo(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createtimespan(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Array Functions ===== */
cfml_value_t *cfml_func_arraynew(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraylen(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayappend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayprepend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraydeleteat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayinsertat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraysort(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraytolist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayfind(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayfindnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraycontains(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraycontainsnocase(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayclear(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayresize(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayisempty(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraymin(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraymax(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraysum(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayavg(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayswap(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayreverse(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayset(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayslice(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraymerge(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayeach(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arraymap(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayfilter(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_arrayreduce(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Struct Functions ===== */
cfml_value_t *cfml_func_structnew(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structkeyexists(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structkeylist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structkeyarray(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structcount(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structdelete(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structclear(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structcopy(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structfind(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structfindkey(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structfindvalue(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structinsert(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structupdate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structappend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structisempty(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structget(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structeach(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structmap(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structfilter(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structsort(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_structtoquery(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Query Functions ===== */
cfml_value_t *cfml_func_querynew(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryaddrow(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querysetcell(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryaddcolumn(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querydeletecolumn(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querydeleterow(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querycolumndata(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querycolumnarray(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querycolumnlist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryrowcount(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querycurrentrow(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querygetrow(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querysort(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryfilter(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_querymap(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryreduce(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryeach(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_queryexecute(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Decision Functions ===== */
cfml_value_t *cfml_func_isdefined(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isnumeric(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isarray(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isstruct(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isquery(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_issimplevalue(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isboolean(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isnull(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isvalid(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isempty(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isobject(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isclosure(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_iscustomfunction(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isinstance(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isbinary(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isxml(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_isjson(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_iswddx(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Conversion Functions ===== */
cfml_value_t *cfml_func_tostring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_tonumeric(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_val(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Encoding/Decoding Functions ===== */
cfml_value_t *cfml_func_urlencodedformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_urldecode(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_htmleditformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_htmlcodeformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_jsstringformat(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_jsonserialize(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_serializejson(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_jsondeserialize(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_deserializejson(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_hash(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_encrypt(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_decrypt(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_tobase64(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_tobinary(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_binaryencode(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_binarydecode(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_charsetencode(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_charsetdecode(cfml_context_t *ctx, ngx_array_t *args);

/* ===== File/System Functions ===== */
cfml_value_t *cfml_func_fileread(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_filewrite(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_fileappend(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_filedelete(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_filemove(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_filecopy(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_fileexists(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_directoryexists(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_directorycreate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_directorydelete(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_directorylist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getdirectoryfrompath(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getfilefrompath(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getfileinfo(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_expandpath(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gettempfile(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gettempdirectory(cfml_context_t *ctx, ngx_array_t *args);

/* ===== Other Functions ===== */
cfml_value_t *cfml_func_evaluate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_de(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_iif(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_writeoutput(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gettickcount(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_sleep(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createuuid(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createguid(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_createobject(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_duplicate(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getfunctionlist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getmetadata(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getbasetagdata(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getbasetaglist(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getcomponentmetadata(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_invoke(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_location(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_throw(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_abort(cfml_context_t *ctx, ngx_array_t *args);

/* HTTP/URL Functions */
cfml_value_t *cfml_func_getcurrenttemplatepath(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getbasetemplatepath(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gethttprequestdata(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_gethttptimestring(cfml_context_t *ctx, ngx_array_t *args);
cfml_value_t *cfml_func_getpagecontext(cfml_context_t *ctx, ngx_array_t *args);

#endif /* _CFML_FUNCTIONS_H_ */
