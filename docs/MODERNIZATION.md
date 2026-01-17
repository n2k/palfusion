# PALfusion Modern Features

### Because CFML Deserves to Play in 2026

---

## The Problem With "Legacy"

Everyone calls CFML legacy. They say it with that tone. The same tone they use when discussing dial-up modems, table-based layouts, and the time they thought NoSQL would replace SQL.

Here's the thing: CFML isn't legacy. CFML is battle-tested. And now it speaks fluent 2026.

PALfusion doesn't just run your grandfather's CFM files. It runs APIs that would make your GraphQL-obsessed coworker nervous. Real-time WebSockets that don't require a Node.js sidecar. S3 uploads signed with the same AWS SigV4 that powers trillion-dollar infrastructure.

This is CFML, evolved.

---

## Tier 1: The Non-Negotiables

### JSON - Because Everything is JSON Now

Remember when XML was the future? We don't either.

```cfm
<!--- Parse that API response --->
<cfset data = DeserializeJSON(httpResponse)>
<cfset userName = data.user.profile.displayName>

<!--- Send it back as JSON --->
<cfset response = {
    "status": "success",
    "timestamp": now(),
    "data": queryToArray(myQuery)
}>
<cfcontent type="application/json">
<cfoutput>#SerializeJSON(response)#</cfoutput>
```

**Functions:**
- `SerializeJSON(value, pretty)` - Convert anything to JSON. Structs, arrays, queries, dates. Pretty-print optional for humans.
- `DeserializeJSON(string)` - Parse JSON back to CFML values. Handles nested objects, arrays, unicode, the works.
- `IsJSON(string)` - Validate before you parse. Because try/catch is for people who don't plan ahead.
- `JSONParse(string)` - Alias for DeserializeJSON. We don't judge your naming preferences.

**What It Actually Does:**
- Full RFC 8259 compliance
- Proper unicode handling (yes, emoji work)
- Query serialization as array of row objects
- ISO 8601 date formatting
- Null preservation (no more empty string surprises)

---

### HTTP Client - Talk to the Outside World

Your CFML shouldn't live in isolation. It needs to call APIs, fetch webhooks, and occasionally remind that legacy Java service that it still exists.

```cfm
<!--- The classic way --->
<cfhttp url="https://api.example.com/users" method="GET" result="response">
    <cfhttpparam type="header" name="Authorization" value="Bearer #token#">
    <cfhttpparam type="header" name="Accept" value="application/json">
</cfhttp>

<cfif response.statusCode eq "200 OK">
    <cfset users = DeserializeJSON(response.fileContent)>
</cfif>

<!--- The new way --->
<cfscript>
    response = HTTPRequest({
        url: "https://api.example.com/users",
        method: "POST",
        headers: {
            "Authorization": "Bearer " & token,
            "Content-Type": "application/json"
        },
        body: SerializeJSON(userData),
        timeout: 30
    });
</cfscript>
```

**What You Get:**
- HTTP/HTTPS with proper TLS 1.3
- Connection pooling (reuse those TCP handshakes)
- Automatic redirect following
- Timeout controls (connect, read, total)
- Basic auth, Bearer tokens, custom headers
- Form posts, JSON bodies, multipart uploads
- Response parsing into usable structs

**No External Dependencies:**
Uses BSD sockets and OpenSSL directly. No libcurl. No "http client library that wraps another http client library." Just sockets, like adults.

---

### JWT/OAuth2 - Security That Actually Secures

Every API needs auth. Most implementations are wrong. PALfusion does it right.

```cfm
<!--- Validate incoming JWT --->
<cfscript>
    token = GetHTTPRequestData().headers["Authorization"];
    token = Replace(token, "Bearer ", "");
    
    jwt = JWTDecode(token);
    
    if (!jwt.valid) {
        cfheader(statusCode="401", statusText="Unauthorized");
        abort;
    }
    
    // Token is valid, check claims
    if (jwt.claims.exp < now()) {
        cfheader(statusCode="401", statusText="Token Expired");
        abort;
    }
    
    userId = jwt.claims.sub;
</cfscript>

<!--- Verify against JWKS (for OAuth2/OIDC) --->
<cfscript>
    jwks = JWKSFetch("https://auth.example.com/.well-known/jwks.json");
    isValid = JWTVerify(token, jwks);
</cfscript>

<!--- Generate your own tokens --->
<cfscript>
    claims = {
        "sub": user.id,
        "email": user.email,
        "iat": now(),
        "exp": dateAdd("h", 24, now())
    };
    
    token = JWTEncode(claims, application.jwtSecret, "HS256");
</cfscript>
```

**Functions:**
- `JWTDecode(token)` - Parse and decode JWT, returns struct with header, claims, validity
- `JWTEncode(claims, secret, algorithm)` - Create signed JWTs (HS256, HS384, HS512)
- `JWTVerify(token, keyOrJWKS)` - Verify signature against secret or JWKS
- `JWKSFetch(url)` - Retrieve and cache JWKS from identity provider
- `OAuth2AuthURL(config)` - Build OAuth2 authorization URLs with PKCE

**Supported Algorithms:**
- HMAC: HS256, HS384, HS512
- RSA: RS256, RS384, RS512 (via JWKS)
- ECDSA: ES256, ES384, ES512 (via JWKS)

---

## Tier 2: The Competitive Advantages

### Redis/Valkey - Because Shared Memory Has Limits

nginx shared memory is great until you need to scale past one server. Redis is the answer. Valkey is the open-source answer.

```cfm
<!--- Connect --->
<cfscript>
    redis = RedisConnect("localhost", 6379);
    RedisAuth(redis, "yourpassword");
</cfscript>

<!--- Basic operations --->
<cfscript>
    RedisSet("user:1001", SerializeJSON(userData), 3600); // 1 hour TTL
    cachedUser = DeserializeJSON(RedisGet("user:1001"));
    
    RedisDelete("session:expired");
    exists = RedisExists("feature:flag:darkmode");
</cfscript>

<!--- Hash operations --->
<cfscript>
    RedisHSet("user:1001:prefs", "theme", "dark");
    RedisHSet("user:1001:prefs", "language", "en");
    
    allPrefs = RedisHGetAll("user:1001:prefs");
    // Returns: { theme: "dark", language: "en" }
</cfscript>

<!--- High-level cache API --->
<cfscript>
    // CachePut auto-serializes CFML values
    CachePut("dashboard:stats", complexStruct, 300);
    
    stats = CacheGet("dashboard:stats");
    // Returns deserialized struct, or null if expired
    
    CacheRemove("dashboard:stats");
</cfscript>
```

**What's Implemented:**
- Native RESP protocol (no hiredis dependency)
- Connection management with auth and DB selection
- String commands: GET, SET, DEL, EXISTS, EXPIRE, TTL, INCR, DECR
- Hash commands: HSET, HGET, HGETALL, HDEL, HEXISTS
- List commands: LPUSH, RPUSH, LPOP, RPOP, LLEN
- Set commands: SADD, SREM, SISMEMBER, SCARD
- Pub/Sub: PUBLISH (SUBSCRIBE requires event loop integration)
- Transactions: MULTI, EXEC, DISCARD

**Automatic Serialization:**
Complex CFML values (structs, arrays, queries) are automatically JSON-serialized when stored and deserialized when retrieved. You don't think about it. It just works.

---

### Server-Sent Events - Real-Time Without the Complexity

WebSockets are great. They're also complex. Sometimes you just need to push data to clients. SSE does exactly that.

```cfm
<!--- Initialize SSE stream --->
<cfscript>
    SSEInit(); // Sets headers, starts stream
    
    // Send events
    SSESend("Hello, client!");
    
    // Named events
    SSESend(eventType="userJoined", data=SerializeJSON({
        "userId": 1001,
        "username": "pal"
    }));
    
    // With event ID for reconnection
    SSESend(id="evt-001", data="Important message");
    
    // Set retry interval
    SSESetRetry(5000); // 5 second reconnect
    
    // Close when done
    SSEClose();
</cfscript>
```

**Client-Side:**
```javascript
const events = new EventSource('/api/stream.cfm');

events.onmessage = (e) => console.log(e.data);

events.addEventListener('userJoined', (e) => {
    const user = JSON.parse(e.data);
    showNotification(`${user.username} joined!`);
});
```

**Features:**
- Proper `text/event-stream` content type
- Automatic `Cache-Control: no-cache`
- `X-Accel-Buffering: no` for nginx proxy compatibility
- Event IDs for client reconnection (`Last-Event-ID` header)
- Named event types
- Configurable retry intervals
- Comment support for keepalive

**When to Use SSE vs WebSocket:**
- SSE: Server pushes data to client. Notifications, live feeds, progress updates.
- WebSocket: Bidirectional communication. Chat, games, collaborative editing.

If you're only pushing data one way, SSE is simpler, uses standard HTTP, and works through more proxies.

---

### WebSockets - Full Bidirectional Communication

When you need real two-way communication, WebSockets are the answer. PALfusion implements RFC 6455 directly in the nginx event loop.

```cfm
<!--- Check for WebSocket upgrade and accept --->
<cfscript>
    result = WSAccept();
    
    if (!result.success) {
        cfheader(statusCode="400", statusText="Bad Request");
        WriteOutput("Not a WebSocket request");
        abort;
    }
    
    // Connection established
    // The connection now lives in nginx's event loop
</cfscript>
```

```cfm
<!--- Send messages --->
<cfscript>
    // Text message
    WSSend("Hello, client!");
    
    // JSON data (auto-serialized)
    WSSend({
        "type": "update",
        "data": queryToArray(latestData)
    });
    
    // Broadcast to ALL connected clients
    count = WSBroadcast({
        "type": "announcement",
        "message": "Server maintenance in 5 minutes"
    });
    WriteLog("Broadcast sent to #count# clients");
    
    // Close with status code and reason
    WSClose(1000, "Goodbye");
</cfscript>
```

**What's Implemented:**
- Full RFC 6455 handshake (Sec-WebSocket-Key/Accept)
- Frame encoding with proper length handling (125/16-bit/64-bit)
- Automatic payload masking/unmasking
- Text and binary frame support
- Ping/pong keepalive
- Close handshake with status codes
- Connection registry for broadcast
- Event-driven in nginx's event loop

**Not a Toy Implementation:**
This isn't "WebSocket but actually long-polling." It's real WebSocket frames over a persistent TCP connection, managed by nginx's battle-tested event loop.

---

## Tier 3: The Nice-to-Haves That Became Must-Haves

### MessagePack - Binary JSON for the Size-Conscious

JSON is human-readable. Sometimes you don't need human-readable. You need small and fast.

```cfm
<cfscript>
    data = {
        "users": queryToArray(userQuery),
        "metadata": {
            "generated": now(),
            "count": userQuery.recordCount
        }
    };
    
    // JSON: ~2.4KB
    jsonData = SerializeJSON(data);
    
    // MessagePack: ~1.6KB (33% smaller)
    binaryData = MsgPackEncode(data);
    
    // Send as binary
    cfcontent(type="application/msgpack", variable=binaryData);
</cfscript>
```

**Functions:**
- `MsgPackEncode(value)` - Serialize CFML value to MessagePack binary
- `MsgPackDecode(binary)` - Deserialize MessagePack back to CFML

**Why MessagePack:**
- 30-50% smaller than JSON for typical data
- Faster to parse (no string escaping/unescaping)
- Native binary support (no Base64 overhead)
- Used by: Redis, Fluentd, Unity, countless game engines

---

### S3 Storage - Object Storage Without the SDK

Every cloud has S3-compatible storage. AWS S3. Cloudflare R2. MinIO. Backblaze B2. They all speak the same protocol.

```cfm
<!--- Configure (once, at application start) --->
<cfscript>
    application.s3 = {
        endpoint: "s3.amazonaws.com",
        region: "us-east-1",
        accessKey: "AKIA...",
        secretKey: "...",
        bucket: "my-bucket"
    };
</cfscript>

<!--- Upload --->
<cfscript>
    S3Put(
        key = "uploads/2026/01/report.pdf",
        data = fileReadBinary(uploadedFile),
        contentType = "application/pdf"
    );
</cfscript>

<!--- Download --->
<cfscript>
    pdfData = S3Get("uploads/2026/01/report.pdf");
    cfcontent(type="application/pdf", variable=pdfData);
</cfscript>

<!--- Generate presigned URL for direct upload --->
<cfscript>
    uploadUrl = S3Presign(
        key = "uploads/user-#userId#/#createUUID()#.jpg",
        expires = 3600,  // 1 hour
        isPut = true
    );
    // Give URL to client for direct-to-S3 upload
</cfscript>

<!--- List objects --->
<cfscript>
    files = S3List(prefix = "uploads/2026/01/", maxKeys = 100);
    for (file in files) {
        WriteOutput("#file.key# - #file.size# bytes<br>");
    }
</cfscript>
```

**Full AWS Signature V4:**
This isn't a wrapper around the AWS CLI. It's a complete SigV4 implementation:
- HMAC-SHA256 signing key derivation
- Canonical request construction
- String-to-sign generation
- Presigned URL generation (up to 7 days)

Works with any S3-compatible service. No AWS SDK required.

---

### OpenTelemetry - Observability That Actually Observes

You can't fix what you can't see. OpenTelemetry is the industry standard for distributed tracing. Now your CFML participates.

```cfm
<!--- Configure at application start --->
<cfscript>
    TraceConfig({
        endpoint: "https://otel-collector.example.com:4318",
        serviceName: "palfusion-api",
        protocol: "http"  // or "grpc"
    });
</cfscript>

<!--- Trace a request --->
<cfscript>
    span = TraceStart("handleUserRequest", "server");
    
    try {
        TraceSet("user.id", userId);
        TraceSet("http.method", cgi.request_method);
        TraceSet("http.url", cgi.script_name);
        
        // Do work...
        result = processRequest();
        
        TraceEvent("requestProcessed", {
            "resultCount": arrayLen(result.items)
        });
        
        TraceEnd("ok");
        
    } catch (any e) {
        TraceSet("error", true);
        TraceSet("error.message", e.message);
        TraceEnd("error", e.message);
        rethrow;
    }
</cfscript>
```

**What Gets Traced:**
- Trace ID (128-bit, propagated across services)
- Span ID (64-bit, unique per operation)
- Parent span (for nested operations)
- Timing (start/end in nanoseconds)
- Attributes (key-value metadata)
- Events (timestamped occurrences within span)
- Status (ok/error with message)

**W3C Trace Context:**
Incoming `traceparent` and `tracestate` headers are automatically parsed. Outgoing HTTP requests (via cfhttp) can inject trace context for distributed tracing across services.

**Export Protocols:**
- **HTTP OTLP**: POST to `/v1/traces` with JSON payload
- **gRPC-Web**: For gRPC collectors (uses `application/grpc-web+json`)

Compatible with: Jaeger, Zipkin, Datadog, Honeycomb, Grafana Tempo, AWS X-Ray, and any OTLP-compatible collector.

---

## The Philosophy

These aren't features bolted on because "everyone else has them." Each one exists because real applications need them:

- **JSON**: Because every API you'll ever call returns JSON
- **HTTP Client**: Because your app doesn't exist in isolation
- **JWT/OAuth2**: Because security isn't optional
- **Redis**: Because state needs to scale
- **SSE/WebSocket**: Because users expect real-time
- **MessagePack**: Because bandwidth costs money
- **S3**: Because files need to live somewhere
- **OpenTelemetry**: Because you need to debug production

This is CFML for 2026. Not a museum piece. A living, breathing runtime that speaks the protocols your infrastructure expects.

---

## What's Next

The foundation is laid. The protocols are implemented. Now we ship.

```cfm
<cfoutput>
    #dateFormat(now(), "yyyy")#: The year CFML stopped apologizing.
</cfoutput>
```

---

*"Legacy is just another word for 'survived long enough to prove it works.'"*
