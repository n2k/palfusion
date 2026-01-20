# PALfusion

### The Web3-Native, Edge-Aware, AI-Driven Meta-Framework for ColdFusion Markup Language

**A Movement. A Manifesto. A Memorial.**

---

## The Origin Story

It was 3 AM during the dotcom bubble of 2000. The glow of a CRT monitor illuminated a large empty Bürolandschaft in Stockholm. Empty coffee cups formed a skyline on the desk. Pål Brattberg was shipping code.

Not "pushing to staging." Not "opening a PR for review." SHIPPING. The kind of shipping that built the internet. Raw, unfiltered, caffeine-fueled creation that turned ideas into reality before the sun came up.

PALfusion exists because somewhere along the way, we lost that spirit. We got buried under layers of abstraction, drowned in configuration files, paralyzed by the paradox of choice between seventeen different state management solutions. We started asking AI to write our code instead of writing it ourselves.

This project is a tribute. A plea. A bat-signal to the hacker spirit that built Web 1.0.

**Pål, if you're reading this: stop scrolling. Stop prompting. Start shipping.**

---

## What Is PALfusion

PALfusion is a zero-dependency, edge-native nginx module that executes ColdFusion Markup Language at the speed of C. No JVM. No container orchestration. No twelve-factor app compliance checklist. Just nginx and your .cfm files, running at the edge, closer to your users than your competitors thought possible.

In an era where the average "hello world" requires 847 npm packages and a Kubernetes cluster, PALfusion asks a radical question: what if we just... didn't do that?

### The Technical Reality

```
Request -> nginx -> PALfusion -> Response
```

That's it. That's the architecture diagram. Print it out and frame it next to your "microservices mesh topology" poster as a reminder of what simplicity looks like.

---

## Why This Matters in 2026

The industry has mass-adopted AI-driven development. Copilots write our functions. LLMs architect our systems. We've optimized for prompt engineering over actual engineering.

But here's what the AI aggregators won't tell you: somewhere in the noise of generated boilerplate, we forgot how to build things that are genuinely fast, genuinely simple, and genuinely ours.

PALfusion is not AI-generated slop. Every line of C in this codebase exists because a human decided it should exist. This is hand-crafted, artisanal systems programming for developers who remember what it felt like to understand their entire stack.

### The Philosophy

- **Edge Awareness**: Your code runs where nginx runs. That's everywhere. CDN nodes, IoT gateways, that Raspberry Pi in your closet. True edge computing, not "edge" as a marketing term for "our data centers are slightly closer."

- **Zero Boilerplate**: No starter templates. No scaffolding CLIs. No "create-palfusion-app" that generates 200 files you'll never read. Write a .cfm file. Put it in a directory. It works.

- **Anti-Framework Framework**: PALfusion is a meta-framework in the truest sense - it's the framework you use when you're tired of frameworks. It's the TypeScript alternative for people who realized the type safety they needed was the friends they made along the way.

- **Web3 Compatible**: Your CFML runs on the same servers that run blockchain nodes. That's Web3 compatibility. We're not adding NFT minting functions, but we're not stopping you either.

---

## Installation

### Building From Source

Like all good things, PALfusion requires you to compile it yourself. This is a feature, not a bug. If you can't compile C code, you probably shouldn't be running C code in production.

```bash
# Get nginx source (because we link directly, like adults)
wget http://nginx.org/download/nginx-1.26.0.tar.gz
tar xzf nginx-1.26.0.tar.gz
cd nginx-1.26.0

# Configure with PALfusion
./configure \
    --add-module=/path/to/palfusion \
    --with-http_ssl_module

# Build it
make

# Install it
sudo make install
```

### Dependencies

- PCRE (because regex is eternal)
- OpenSSL (because security matters)
- libmysqlclient (optional, for MySQL)
- libpq (optional, for PostgreSQL)
- libsqlite3 (optional, for SQLite)

That's five dependencies. Count them. Five. The node_modules of your TanStack Start project has more dependencies in its dependency tree for parsing a single JSON file.

---

## Configuration

```nginx
http {
    # Enable the revolution
    cfml_cache on;
    cfml_cache_size 100m;
    cfml_session_timeout 30m;
    
    # Database connections (yes, real databases, not Firebase)
    cfml_datasource maindb "mysql://user:pass@localhost:3306/myapp";
    cfml_datasource analytics "postgresql://user:pass@localhost:5432/metrics";
    cfml_datasource local "sqlite:///var/data/app.db";
    
    server {
        listen 80;
        server_name localhost;
        root /var/www/html;
        
        location ~ \.(cfm|cfc)$ {
            cfml on;
        }
    }
}
```

---

## The Stack

### What PALfusion Replaces

| Bloated Solution | PALfusion Equivalent |
|-----------------|---------------------|
| Node.js + Express + 400 middleware | nginx + PALfusion |
| Docker + Kubernetes + Helm + ArgoCD | Just run nginx |
| React + Next.js + Vercel + Edge Functions | cfoutput tags |
| Prisma + PostgreSQL + Redis + Memcached | cfquery + nginx shared memory |
| JWT + OAuth2 + Auth0 + Session Store | cfml_session |

### What PALfusion Does NOT Replace

Your ability to think critically about architecture decisions. Your responsibility to understand what your code does. Your duty to ship things that actually work.

---

## Features

### CFScript Support

Full ECMAScript-inspired scripting syntax because sometimes tags feel too verbose:

```javascript
<cfscript>
component {
    public function calculateRevenue(required numeric units, numeric price = 9.99) {
        var total = units * price;
        
        if (total > 10000) {
            return total * 0.9; // Bulk discount
        }
        
        return total;
    }
}
</cfscript>
```

### Shared Memory Sessions

Sessions that actually persist across nginx workers using ngx_slab shared memory. No Redis required. No "session affinity" load balancer hacks. Just sessions that work.

```cfm
<cfset session.user = "pal">
<cfset session.lastActive = now()>
```

### Native Database Connectivity

MySQL, PostgreSQL, and SQLite - compiled in, running at C speed:

```cfm
<cfquery name="users" datasource="maindb">
    SELECT * FROM users WHERE active = 1
</cfquery>

<cfoutput query="users">
    #username# - #email#<br>
</cfoutput>
```

### Component-Oriented Architecture

CFCs that would make any enterprise architect weep with joy:

```cfm
<cfcomponent>
    <cffunction name="init" returntype="UserService">
        <cfreturn this>
    </cffunction>
    
    <cffunction name="getUser" returntype="struct">
        <cfargument name="id" type="numeric" required="true">
        <cfquery name="local.user" datasource="maindb">
            SELECT * FROM users WHERE id = <cfqueryparam value="#arguments.id#">
        </cfquery>
        <cfreturn local.user>
    </cffunction>
</cfcomponent>
```

---

## Supported CFML Tags

The classics. The hits. The tags that powered a generation of web applications:

cfset, cfoutput, cfif, cfelseif, cfelse, cfswitch, cfcase, cfdefaultcase, cfloop, cfbreak, cfcontinue, cffunction, cfargument, cfreturn, cfcomponent, cfproperty, cfquery, cfqueryparam, cftransaction, cfstoredproc, cfprocparam, cfprocresult, cfinclude, cfmodule, cfinvoke, cfobject, cftry, cfcatch, cfthrow, cfrethrow, cffinally, cfparam, cfdump, cflog, cfabort, cfexit, cflocation, cfheader, cfcontent, cfcookie, cfhtmlhead, cfflush, cfsetting, cfsavecontent, cfsilent, cflock, cfthread, cffile, cfdirectory, cfhttp, cfhttpparam, cfmail, cfmailparam, cfpdf, cfimage, cfcache, cfschedule, cfapplication, cfsession, cferror

---

## Supported Built-in Functions

Over 150 functions. The entire CFML standard library, implemented in C:

**String**: Len, Trim, LTrim, RTrim, UCase, LCase, Left, Right, Mid, Find, FindNoCase, Replace, ReplaceNoCase, Reverse, RepeatString, Compare, CompareNoCase, SpanIncluding, SpanExcluding, Insert, RemoveChars, Asc, Chr, Val, ToString, JSStringFormat, HTMLEditFormat, URLEncodedFormat, URLDecode, REFind, REFindNoCase, REReplace, REReplaceNoCase, REMatch, REMatchNoCase

**Numeric**: Abs, Ceiling, Floor, Round, Int, Fix, Sgn, Max, Min, Rand, RandRange, Randomize, Sqr, Log, Log10, Exp, Sin, Cos, Tan, ASin, ACos, ATan, Pi, BitAnd, BitOr, BitXor, BitNot, BitSHLN, BitSHRN

**Date/Time**: Now, CreateDate, CreateDateTime, CreateTime, CreateTimeSpan, DateFormat, TimeFormat, DateAdd, DateDiff, DatePart, Day, Month, Year, Hour, Minute, Second, DayOfWeek, DayOfYear, DaysInMonth, FirstDayOfMonth, Week, Quarter, IsDate, ParseDateTime, LSDateFormat, LSTimeFormat

**Array**: ArrayNew, ArrayLen, ArrayAppend, ArrayPrepend, ArrayDeleteAt, ArrayInsertAt, ArraySort, ArrayResize, ArraySet, ArraySwap, ArrayToList, ArrayClear, ArrayIsEmpty, ArrayFind, ArrayFindNoCase, ArrayContains, ArrayContainsNoCase, ArrayAvg, ArraySum, ArrayMin, ArrayMax

**Struct**: StructNew, StructKeyExists, StructKeyList, StructCount, StructDelete, StructClear, StructCopy, StructAppend, StructFind, StructFindKey, StructFindValue, StructGet, StructInsert, StructIsEmpty, StructSort, StructUpdate

**Query**: QueryNew, QueryAddRow, QuerySetCell, QueryAddColumn, QueryDeleteColumn, QueryDeleteRow, ValueList, QuotedValueList, QueryColumnList, QueryRecordCount, QueryCurrentRow

**Decision**: IsDefined, IsNull, IsNumeric, IsDate, IsBoolean, IsSimpleValue, IsArray, IsStruct, IsQuery, IsObject, IsCustomFunction, IsBinary, IsJSON, IsXML, IsValid

**Encoding**: Hash, Encrypt, Decrypt, GenerateSecretKey, ToBase64, ToBinary, BinaryEncode, BinaryDecode, CharsetEncode, CharsetDecode

**Other**: CreateUUID, CreateGUID, Duplicate, GetTickCount, Sleep, WriteOutput, GetMetaData, GetComponentMetaData, Invoke, Evaluate, DE, IIF, SerializeJSON, DeserializeJSON

---

## The Movement

PALfusion is more than code. It's a statement about what we've lost and what we can reclaim.

We lost the joy of understanding our systems top to bottom. We lost the thrill of shipping without permission. We lost the ability to debug without consulting seventeen different observability dashboards.

The dotcom era had problems. Plenty of them. But it also had builders who shipped first and asked for funding later. Hackers who learned by doing, not by prompting. Developers who could explain exactly what every line of their code did because they wrote every line themselves.

PALfusion is an invitation to build like that again.

---

## For Pål

This project exists because of late nights in 2000 when one developer proved that shipping beats talking about shipping. That coffee-fueled sessions produce better code than committee meetings. That the best architecture is the one that actually gets deployed.

The tech industry needs that energy back. Not the hustle culture toxicity. Not the "move fast and break things" that became "move fast and break democracy." The genuine, pure, creative energy of someone who loves building things and can't stop until they're done.

Pål, the cursor is blinking. The coffee is brewing. The internet still needs people who actually build things.

Stop with the AI-slop. Start shipping.

---

## Contributing

Read CONTRIBUTING.md. But more importantly: if you have an idea, build it. Don't open an issue asking if you should build it. Build it. Submit a PR. Ship something.

That's the PALfusion way.

---

## License

MIT. Because freedom matters and lawyers are expensive.

---

## Links

- Source: [https://github.com/n2k/palfusion](https://github.com/n2k/palfusion)
- Pål Brattberg: [https://github.com/pal](https://github.com/pal)

---

*"The best code is code that ships."*
*- Every developer at 3 AM who ever actually built something*
