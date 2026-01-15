# vim:set ft=perl ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket 'no_plan';

our $HttpConfig = <<'_EOC_';
    cfml_cache off;
_EOC_

run_tests();

__DATA__

=== TEST 1: basic cfscript block
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
x = 10;
y = 20;
writeOutput(x + y);
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 30
--- no_error_log
[error]



=== TEST 2: cfscript if statement
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
value = 15;
if (value > 10) {
    writeOutput("greater");
} else {
    writeOutput("lesser");
}
</cfscript>
--- request
GET /test.cfm
--- response_body_like: greater
--- no_error_log
[error]



=== TEST 3: cfscript for loop
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
result = "";
for (i = 1; i <= 5; i++) {
    result &= i;
}
writeOutput(result);
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 12345
--- no_error_log
[error]



=== TEST 4: cfscript while loop
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
count = 0;
while (count < 3) {
    writeOutput(count);
    count++;
}
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 012
--- no_error_log
[error]



=== TEST 5: cfscript function definition
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
function multiply(a, b) {
    return a * b;
}
writeOutput(multiply(6, 7));
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 42
--- no_error_log
[error]



=== TEST 6: cfscript array literal
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
arr = [1, 2, 3, 4, 5];
writeOutput(arrayLen(arr));
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 5
--- no_error_log
[error]



=== TEST 7: cfscript struct literal
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
person = {name: "John", age: 30};
writeOutput(person.name);
</cfscript>
--- request
GET /test.cfm
--- response_body_like: John
--- no_error_log
[error]



=== TEST 8: cfscript ternary operator
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
x = 10;
result = x > 5 ? "yes" : "no";
writeOutput(result);
</cfscript>
--- request
GET /test.cfm
--- response_body_like: yes
--- no_error_log
[error]



=== TEST 9: cfscript try-catch
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfscript>
try {
    x = 1;
    writeOutput("success");
} catch (any e) {
    writeOutput("error");
}
</cfscript>
--- request
GET /test.cfm
--- response_body_like: success
--- no_error_log
[error]



=== TEST 10: cfscript component
--- http_config eval: $::HttpConfig
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> Calculator.cfc
component {
    public numeric function add(required numeric a, required numeric b) {
        return a + b;
    }
    
    public numeric function subtract(required numeric a, required numeric b) {
        return a - b;
    }
}
>>> test.cfm
<cfscript>
calc = new Calculator();
writeOutput(calc.add(10, 5));
</cfscript>
--- request
GET /test.cfm
--- response_body_like: 15
--- no_error_log
[error]
