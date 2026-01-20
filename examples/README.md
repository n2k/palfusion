# PALfusion Examples

### Code That Ships

---

## realtime-saas-api.cfm

**The Mic Drop.**

A complete, production-ready SaaS backend in a single file:

| Feature | Included |
|---------|----------|
| REST API (CRUD) | Yes |
| JWT Authentication | Yes |
| JWKS Validation | Yes |
| WebSocket Real-time | Yes |
| Server-Sent Events | Yes |
| Redis Caching | Yes |
| SQLite Database | Yes |
| S3 File Uploads | Yes |
| OpenTelemetry Tracing | Yes |
| Event Analytics | Yes |

**Lines of code:** ~400

**What you'd need in Node.js:**

```
express
socket.io  
ioredis
prisma
@prisma/client
@auth0/jwks-rsa
jsonwebtoken
aws-sdk
@opentelemetry/sdk-node
@opentelemetry/api
@opentelemetry/exporter-trace-otlp-http
passport
passport-jwt
cors
helmet
compression
express-rate-limit
express-validator
winston
dotenv
```

Plus:
- 200MB of node_modules
- 47 configuration files
- A Dockerfile
- A docker-compose.yml
- Kubernetes manifests
- A CI/CD pipeline to deploy all of it
- A team meeting to discuss the architecture
- Another meeting to discuss the meeting

**What you need with PALfusion:**

```
nginx -c /path/to/nginx.conf
```

---

## Running the Example

```nginx
# nginx.conf
http {
    cfml_datasource local "sqlite:///var/data/palfusion.db";
    
    server {
        listen 8080;
        root /path/to/examples;
        
        location /api {
            cfml on;
            rewrite ^/api(.*)$ /realtime-saas-api.cfm$1 break;
        }
    }
}
```

```bash
# Start nginx
nginx

# Test health endpoint
curl http://localhost:8080/api/health

# Create a user
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"email":"pal@example.com","name":"Pål Brattberg"}'

# Connect WebSocket
wscat -c ws://localhost:8080/api/ws

# Stream events via SSE
curl http://localhost:8080/api/events/stream
```

---

## The Philosophy

These examples aren't toys. They're not "getting started" boilerplate that you'll rewrite entirely before production.

They're patterns. Real patterns for real applications.

The kind of code that ships at 3 AM because you had an idea and couldn't sleep until it was done.

---

*"Show me the code."*
*- Linus Torvalds*

*"Here it is."*
*- PALfusion*
