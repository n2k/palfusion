# vim:set ft=perl ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket 'no_plan';

our $HttpConfig = <<'_EOC_';
    cfml_cache off;
_EOC_

run_tests();

__DATA__

=== TEST 1: basic cfoutput
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset greeting = "Hello">
<cfoutput>#greeting#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: Hello
--- no_error_log
[error]



=== TEST 2: numeric operations
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset a = 10>
<cfset b = 3>
<cfoutput>#a + b#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: 13
--- no_error_log
[error]



=== TEST 3: cfif conditional
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset x = 5>
<cfif x gt 3>
greater
<cfelse>
lesser
</cfif>
--- request
GET /test.cfm
--- response_body_like: greater
--- no_error_log
[error]



=== TEST 4: cfloop index
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfloop from="1" to="3" index="i"><cfoutput>#i#</cfoutput></cfloop>
--- request
GET /test.cfm
--- response_body_like: 123
--- no_error_log
[error]



=== TEST 5: URL scope
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfif isDefined("url.name")>
<cfoutput>Hello #url.name#</cfoutput>
<cfelse>
No name
</cfif>
--- request
GET /test.cfm?name=World
--- response_body_like: Hello World
--- no_error_log
[error]



=== TEST 6: string functions
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset s = "hello">
<cfoutput>#ucase(s)#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: HELLO
--- no_error_log
[error]



=== TEST 7: array operations
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset arr = ["a", "b", "c"]>
<cfoutput>#arrayLen(arr)#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: 3
--- no_error_log
[error]



=== TEST 8: struct operations
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset s = structNew()>
<cfset s.name = "test">
<cfoutput>#s.name#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: test
--- no_error_log
[error]



=== TEST 9: cffunction definition
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cffunction name="add" returntype="numeric">
    <cfargument name="a" type="numeric" required="true">
    <cfargument name="b" type="numeric" required="true">
    <cfreturn arguments.a + arguments.b>
</cffunction>
<cfoutput>#add(5, 7)#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: 12
--- no_error_log
[error]



=== TEST 10: cfparam with default
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfparam name="message" default="default value">
<cfoutput>#message#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: default value
--- no_error_log
[error]



=== TEST 11: date functions
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset d = now()>
<cfoutput>#isDate(d)#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: (true|YES|1)
--- no_error_log
[error]



=== TEST 12: math functions
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfoutput>#abs(-5)#,#ceiling(4.2)#,#floor(4.8)#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: 5,5,4
--- no_error_log
[error]



=== TEST 13: cfsavecontent
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfsavecontent variable="captured">
captured content
</cfsavecontent>
<cfoutput>#len(captured) gt 0#</cfoutput>
--- request
GET /test.cfm
--- response_body_like: (true|YES|1)
--- no_error_log
[error]



=== TEST 14: nested cfif
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset x = 10>
<cfif x gt 5>
<cfif x gt 8>
very high
<cfelse>
high
</cfif>
<cfelse>
low
</cfif>
--- request
GET /test.cfm
--- response_body_like: very high
--- no_error_log
[error]



=== TEST 15: cfloop list
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfset items = "a,b,c">
<cfloop list="#items#" index="item"><cfoutput>#item#</cfoutput></cfloop>
--- request
GET /test.cfm
--- response_body_like: abc
--- no_error_log
[error]
