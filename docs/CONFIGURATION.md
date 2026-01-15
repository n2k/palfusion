# ngx_http_cfml_module Configuration Guide

## Overview

This document provides detailed configuration options for the nginx CFML module.

## Directives

### cfml

**Syntax:** `cfml on | off`  
**Default:** `cfml off`  
**Context:** location

Enables or disables CFML processing for the location.

```nginx
location ~ \.(cfm|cfc)$ {
    cfml on;
}
```

### cfml_root

**Syntax:** `cfml_root path`  
**Default:** document root  
**Context:** http, server, location

Sets the root directory for CFML files. If not specified, uses the standard document root.

```nginx
cfml_root /var/www/cfml;
```

### cfml_index

**Syntax:** `cfml_index file [file ...]`  
**Default:** `index.cfm`  
**Context:** http, server, location

Defines index files for directories. Multiple files can be specified.

```nginx
cfml_index index.cfm Application.cfm default.cfm;
```

### cfml_cache

**Syntax:** `cfml_cache on | off`  
**Default:** `cfml_cache off`  
**Context:** http, server, location

Enables caching of parsed CFML templates. Recommended for production.

```nginx
cfml_cache on;
```

### cfml_cache_size

**Syntax:** `cfml_cache_size size`  
**Default:** `10m`  
**Context:** http, server

Sets the maximum size of the template cache.

```nginx
cfml_cache_size 50m;
```

### cfml_fastcgi_pass

**Syntax:** `cfml_fastcgi_pass address`  
**Default:** none  
**Context:** location

Proxies complex CFML operations to an external CFML engine (Lucee, Adobe ColdFusion) via FastCGI. Use this for operations not supported natively.

```nginx
cfml_fastcgi_pass 127.0.0.1:8888;
```

### cfml_error_page

**Syntax:** `cfml_error_page path`  
**Default:** none  
**Context:** http, server, location

Custom error template for CFML errors.

```nginx
cfml_error_page /errors/cfml_error.cfm;
```

### cfml_strict_mode

**Syntax:** `cfml_strict_mode on | off`  
**Default:** `cfml_strict_mode off`  
**Context:** http, server, location

Enables strict CFML parsing mode. When enabled, syntax errors will be more strictly enforced.

### cfml_session_timeout

**Syntax:** `cfml_session_timeout time`  
**Default:** `20m`  
**Context:** http, server

Sets the session timeout duration.

```nginx
cfml_session_timeout 30m;
```

### cfml_application_timeout

**Syntax:** `cfml_application_timeout time`  
**Default:** `1d`  
**Context:** http, server

Sets the application scope timeout.

```nginx
cfml_application_timeout 2d;
```

### cfml_request_timeout

**Syntax:** `cfml_request_timeout time`  
**Default:** `30s`  
**Context:** http, server, location

Maximum time allowed for request processing.

```nginx
cfml_request_timeout 60s;
```

### cfml_max_include_depth

**Syntax:** `cfml_max_include_depth number`  
**Default:** `100`  
**Context:** http, server, location

Maximum depth for nested cfinclude tags to prevent infinite recursion.

```nginx
cfml_max_include_depth 50;
```

### cfml_datasource

**Syntax:** `cfml_datasource name connection_string`  
**Default:** none  
**Context:** http, server

Defines a database datasource for cfquery operations.

```nginx
cfml_datasource mydb "mysql://user:password@localhost:3306/database";
cfml_datasource pgdb "postgresql://user:password@localhost:5432/mydb";
```

## Complete Example Configuration

```nginx
http {
    # Global CFML settings
    cfml_cache on;
    cfml_cache_size 100m;
    cfml_session_timeout 30m;
    cfml_application_timeout 2d;
    
    # Database connections
    cfml_datasource maindb "mysql://cfuser:secret@db.example.com:3306/production";
    
    server {
        listen 80;
        server_name www.example.com;
        root /var/www/html;
        
        # Standard index
        index index.cfm index.html;
        
        # CFML processing
        location ~ \.(cfm|cfc)$ {
            cfml on;
            cfml_root /var/www/html;
            cfml_index index.cfm Application.cfm;
            cfml_request_timeout 60s;
            cfml_max_include_depth 100;
            cfml_strict_mode off;
            
            # For complex queries, proxy to Lucee
            # cfml_fastcgi_pass 127.0.0.1:8888;
        }
        
        # API endpoints (return JSON)
        location /api/ {
            cfml on;
            add_header Content-Type application/json;
        }
        
        # Static files
        location ~* \.(js|css|png|jpg|gif|ico)$ {
            expires 30d;
        }
        
        # Block direct access to includes
        location /includes/ {
            deny all;
        }
    }
    
    # SSL server
    server {
        listen 443 ssl http2;
        server_name www.example.com;
        root /var/www/html;
        
        ssl_certificate /etc/ssl/certs/example.crt;
        ssl_certificate_key /etc/ssl/private/example.key;
        
        location ~ \.(cfm|cfc)$ {
            cfml on;
        }
    }
}
```

## Performance Tuning

### Template Caching

Enable template caching in production:

```nginx
cfml_cache on;
cfml_cache_size 100m;  # Adjust based on number of templates
```

### Worker Processes

CFML processing benefits from multiple worker processes:

```nginx
worker_processes auto;  # Or set to number of CPU cores
```

### Connections

```nginx
events {
    worker_connections 2048;
    multi_accept on;
}
```

## Security Considerations

1. **Block sensitive files:**
   ```nginx
   location ~ /\.(svn|git|htaccess) {
       deny all;
   }
   ```

2. **Restrict CFC access:**
   ```nginx
   location ~ \.cfc$ {
       cfml on;
       # Only allow localhost or specific IPs for remote methods
       allow 127.0.0.1;
       deny all;
   }
   ```

3. **Disable directory listing:**
   ```nginx
   autoindex off;
   ```

4. **Set secure headers:**
   ```nginx
   add_header X-Content-Type-Options nosniff;
   add_header X-Frame-Options SAMEORIGIN;
   add_header X-XSS-Protection "1; mode=block";
   ```

## Troubleshooting

### Debug Mode

For development, you can enable debug output:

```nginx
error_log /var/log/nginx/cfml_error.log debug;
```

### Common Issues

1. **Template not found:** Check cfml_root path
2. **Session not persisting:** Verify session_timeout and cookie settings
3. **Slow performance:** Enable cfml_cache
4. **Memory issues:** Adjust cfml_cache_size
