# PALfusion Test Suite

This directory contains the Test::Nginx-based test suite for PALfusion.

## Prerequisites

Install Test::Nginx:

```bash
cpan Test::Nginx
```

Or on Debian/Ubuntu:

```bash
apt-get install libtest-nginx-perl
```

## Running Tests

Set the path to your nginx binary with the PALfusion module:

```bash
export PATH=/path/to/nginx/sbin:$PATH
```

Run all tests:

```bash
prove -r t/
```

Run a specific test file:

```bash
prove t/000-sanity.t
```

Run with verbose output:

```bash
prove -v t/
```

## Test Files

- `000-sanity.t` - Basic CFML tag functionality
- `001-cfscript.t` - CFScript syntax support

## Writing Tests

Tests use the Test::Nginx::Socket framework. Each test block contains:

- `=== TEST N: description` - Test name
- `--- config` - nginx location config
- `--- user_files` - CFML files to create
- `--- request` - HTTP request to make
- `--- response_body_like` - Expected response pattern
- `--- no_error_log` - Ensure no errors logged

Example:

```perl
=== TEST 1: basic output
--- config
    location /test {
        cfml on;
        root html;
    }
--- user_files
>>> test.cfm
<cfoutput>Hello</cfoutput>
--- request
GET /test.cfm
--- response_body_like: Hello
--- no_error_log
[error]
```
