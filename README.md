# SecureGate

An embedded Web Application Firewall (WAF) for HTTP APIs. It catches seven classes of attack (SQL injection, XSS, path traversal, command injection, SSRF, Log4Shell and NoSQL injection), rate-limits clients by IP, blocks repeat offenders automatically, adds browser security headers, writes every blocked request to a JSON Lines alert log, and comes with a live monitoring dashboard. A **monitor mode** lets you watch what it *would* block before it blocks anything.

It can be deployed in two ways:

| | **Gateway mode** (recommended) | **Embedded mode** |
|---|---|---|
| How | SecureGate runs as its own service *in front of* your app and forwards only clean requests | SecureGate is added as a Maven dependency *inside* your Spring Boot app |
| Works with | **Any** HTTP app: Spring, Node, Python, PHP, .NET, Go… | Spring Boot 3 servlet apps only |
| Changes to your app | None | Add one dependency |
| Enable with | `securegate.proxy.target-url=http://your-app:port` | See [Embedded mode](#embedded-mode-use-securegate-inside-a-spring-boot-app) |

```
Gateway mode
                         ┌──────────────── SecureGate :8080 ────────────────┐
 Internet ──── request ─►│ admin auth → IP block → rate limit → detection   │── clean only ──► your app
                         │ /admin/** and /dashboard are answered locally    │   (no public port)
                         └──────────────────────────────────────────────────┘
                              attacks → 400 / 403 / 429, never reach your app
```

The project also ships a small, intentionally vulnerable demo API to test against.

| | |
|---|---|
| Stack | Java 17, Spring Boot 3.3, Maven, Docker |
| State | In-memory (no Redis or database) |
| Alert log | `logs/alerts.json` (one JSON object per line) |

---

## Gateway mode: protect any app

### With Docker Compose (recommended)

[`docker-compose.yml`](docker-compose.yml) runs SecureGate in front of an app. The example app is `traefik/whoami`, which echoes every request it receives, so you can see exactly what SecureGate forwards.

```bash
docker compose up --build
```

* `http://localhost:8080/anything` goes to the app, through SecureGate.
* `http://localhost:8080/dashboard` opens the SecureGate console.

**To protect your own app**, replace the `app` service with your image or build, and point `SECUREGATE_PROXY_TARGETURL` at its *internal* address. That's the Compose service name plus the port the app listens on inside its container:

```yaml
  securegate:
    environment:
      SECUREGATE_PROXY_TARGETURL: http://app:3000
  app:
    build: ../my-node-app      # no "ports:" section, so it's only reachable through SecureGate
```

### Without Compose

```bash
docker run --rm -p 8080:8080 -e SECUREGATE_PROXY_TARGETURL=http://host.docker.internal:8081 securegate
```

This forwards to an app running on your machine at port 8081. Or run the jar directly:

```bash
java -jar target/securegate-exec.jar --securegate.proxy.target-url=http://localhost:8081
```

### ⚠️ Your app must only be reachable through SecureGate

If clients can still reach the app directly, they simply go around the gateway. With the same request, verified:

```
via SecureGate  :8080  → {"blocked":true,"reason":"SQLi detected",...}
direct to app   :8090  → {"price":19.99,"name":"' OR 1=1 --"}        ← attack went through
```

Ways to prevent this:

* **Docker Compose:** don't publish the app's port. This is what the example file does.
* **Bare metal:** bind the app to `127.0.0.1` only.
* **Cloud:** use a firewall or security-group rule that allows the app's port only from SecureGate.

### What the gateway does with each request

| Step | Behaviour |
|---|---|
| `/admin/**`, `/dashboard` | Served by SecureGate itself, never forwarded |
| Blocked IP / over rate limit / attack / too large | Answered with 403 / 429 / 400 and never forwarded |
| Clean request | Forwarded with the same method, query string, headers and body. The response (status, headers, body) is streamed back. |
| Path | The upstream gets the **canonical** path, the exact one SecureGate inspected. `/api/a;x=1/%62` becomes `/api/a/b`, so your app can't interpret the URL differently from what was checked. |
| Headers added | `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`. Client-sent copies are replaced, not trusted, unless `trust-forwarded-for=true`. |
| Headers removed | `X-Admin-Token` (never leaked upstream) and hop-by-hop headers (`Connection`, `Transfer-Encoding`, …) |
| Redirects | Passed to the client, not followed. A `Location: http://app:3000/next` from the upstream is rewritten to `/next`, so internal hostnames don't leak. |
| Upstream down / slow | `502 {"error":"Upstream unreachable"}` / `504 {"error":"Upstream timed out"}` |

Measured overhead on a local request: about **4 ms** (8.6 ms through the gateway vs 4.8 ms direct).

**Your app sees the client's IP in `X-Real-IP` / `X-Forwarded-For`,** not in its socket address, which is always SecureGate's. In Spring Boot, set `server.forward-headers-strategy=native`. In Express, use `app.set('trust proxy', 1)`. Other frameworks have an equivalent setting.

---

## Run the demo with Docker

```bash
docker build -t securegate .
```

```bash
docker run --rm -p 8080:8080 -e SECUREGATE_ADMIN_TOKEN=change-me -v "$(pwd)/logs:/app/logs" securegate
```

* The image is a multi-stage build: Maven compiles the code and runs the full test suite, then the jar runs on a slim JRE as a non-root user. To skip the tests, run `docker build --build-arg SKIP_TESTS=true -t securegate .`.
* The `-v` mount puts `alerts.json` in `./logs` on your machine. The folder syntax depends on your shell:
  * Bash / Git Bash: `-v "$(pwd)/logs:/app/logs"`
  * Windows PowerShell: `-v "${PWD}/logs:/app/logs"`
  * Windows Command Prompt (cmd): `-v "%cd%\logs:/app/logs"`
* **Set your own `SECUREGATE_ADMIN_TOKEN`.** The default value is `change-me`.

Then open **<http://localhost:8080/dashboard>** and sign in with the admin token.

### Run without Docker

```bash
mvnw.cmd package && java -jar target/securegate-exec.jar
```

The build creates two jars:

* `target/securegate-exec.jar` is the runnable demo app.
* `target/securegate.jar` is a plain library jar that other apps can depend on.

---

## Dashboard

`http://localhost:8080/dashboard` is a monitoring console served by the app itself: three static files (`index.html`, `style.css`, `app.js`) with no external dependencies, no CDN and no inline scripts or styles, so it can run under a strict Content-Security-Policy. Sign in with the admin token. The token stays in that browser tab's session storage and is sent as `X-Admin-Token` on every API call.

| Panel | What it shows / does |
|---|---|
| **Mode button / banner** | Shows **Mode: Enforce** or **Mode: Monitor**. Click to switch at runtime (see [Monitor mode](#monitor-mode-detect-without-blocking)). In monitor mode an amber banner reminds you that nothing is being blocked. |
| **You banner** | Your IP as SecureGate sees it, and how many violations you have toward auto-block. If you're blocked, it turns red and offers an **Unblock me** button. |
| **Stats** | Attacks (blocked or detected, total and last 60 min), how many IPs are blocked now, and the most common attack type |
| **Timeline** | Attacks per minute over the last 30 minutes, stacked by attack type |
| **By type** | Breakdown by attack type (10 types) |
| **Attack console** | One-click presets (SQLi, UNION SELECT, XSS in query and body, path traversal, double-encoded traversal, command injection, Log4Shell, NoSQL injection, SSRF, oversized body) that send *real* requests from your browser and show the response. You can edit the method, URL and body. **Burst test** sends rate-limit + 5 requests to trigger 429s. |
| **Blocked IPs** | Each blocked IP with its reason and a live expiry countdown. Includes **Unblock** buttons and a form to block an IP manually. |
| **Alerts** | The latest alerts, refreshed live every 3 seconds. Filter by type, or search by IP, endpoint or payload. |

Things worth knowing:

* **Your IP will get blocked.** The console sends requests *without* the admin token, so they're treated like any client's. Five attacks get your own IP blocked, which is the point of the demo. Use **Unblock me** to carry on.
* **The dashboard page still loads while you're blocked.** The page itself (and `/favicon.ico`) skips the IP block and the rate limit, so you can always get back in. Attack detection still runs on it, and its data comes only from the token-protected `/admin` API.
* **Attacker payloads are shown as plain text.** They're always inserted with `textContent`, never as HTML. An alert containing `<script>` is displayed, not executed.
* **Theme:** light and dark follow your OS setting. The Theme button overrides it.

---

## Architecture

```
request
  │
  ▼
┌────────────────────────┐  adds X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
│ 0 SecurityHeadersFilter│  Permissions-Policy, COOP, HSTS (HTTPS only); strict CSP on /admin, /dashboard
├────────────────────────┤
│ 1 AdminAuthFilter      │  /admin/** without a valid X-Admin-Token  → 401
│                        │  valid token → marked admin, skips 2-4
├────────────────────────┤
│ 2 IpBlockingFilter     │  IP on the block list                      → 403
├────────────────────────┤
│ 3 RateLimitFilter      │  > max requests in the sliding window      → 429  (+1 violation)
├────────────────────────┤
│ 4 AttackDetectionFilter│  7 detectors + body-size limit             → 400  (+1 violation)
└────────────────────────┘
  │                          N violations within the window → IP auto-blocked (403 from then on)
  │                          In MONITOR mode steps 3 and 4 only log "DETECTED" and let the request pass
  ▼
controllers  (or the upstream app, in gateway mode)
```

```
src/main/java/com/securegate/
  filter/        SecurityHeadersFilter, AdminAuthFilter, IpBlockingFilter, RateLimitFilter,
                 AttackDetectionFilter, ReverseProxyFilter, CachedBodyHttpServletRequest,
                 PrefixedBodyRequest, PathExclusions, RequestPaths, SecurityResponses
  filter/detector/  SqlInjectionDetector, XssDetector, PathTraversalDetector, CommandInjectionDetector,
                 Log4ShellDetector, NoSqlInjectionDetector, SsrfDetector, InputNormalizer
  service/       RateLimiterService, IpBlockingService, AlertLoggerService, ModeService
  controller/    AdminController, DemoController
  model/         AlertEntry, BlockedIp, AttackType, EnforcementMode
  config/        SecurityFilterConfig (auto-configuration), SecurityProperties
src/main/resources/static/dashboard/   monitoring UI: index.html, style.css, app.js (served at /dashboard)
src/test/java/   detector unit tests, quality benchmark, MockMvc integration tests
tools/LoadTest.java   dependency-free load tester (java tools/LoadTest.java <url>)
logs/            alerts.json is written here at runtime
```

### How detection works

**What gets inspected.** The detection filter checks every part of the request:

* the request path and the raw query string
* each parameter name and value, including form-urlencoded bodies
* every header and each cookie
* the request body

JSON bodies are parsed first, and each key and string value is checked on its own. Any other body type is checked as raw text.

**Normalisation.** Before matching, each value is run through `InputNormalizer`. It applies up to 3 rounds of URL decoding, decodes HTML entities (`&lt;`, `&#60;`, `&#x3c;`), removes null bytes and lowercases the value. This means `%2527`, `&#39;` and `oR` can't slip past the patterns.

**Path traversal encodings.** Some tricks don't survive normal decoding, such as overlong UTF-8 (`%c0%af`) and `%00`. The path traversal detector also checks the raw value for these, including their double-encoded forms (`%25c0%25af`, `%2500`).

**The seven detectors.** The first one to match names the attack in the alert, so the order matters: Log4Shell and NoSQL run before SSRF, because `${jndi:ldap://...}` also contains a URL scheme that SSRF would flag.

| Detector | Catches | Headers & cookies inspected? |
|---|---|---|
| SQL injection | tautologies (`' OR 1=1`, `') OR ('1'='1`), `UNION SELECT`, comment truncation (`admin'--`), stacked queries, `SLEEP()`/`WAITFOR`, `information_schema`, `xp_cmdshell`, `INTO OUTFILE` | yes |
| XSS | `<script>`, event handlers (`onerror=`), `javascript:` URLs (even with whitespace tricks), `<iframe>`/`<svg>`/`<object>`, `eval(`, `document.cookie`, `srcdoc`, CSS `expression()` | yes |
| Path traversal | `../`, `..\`, `%2e%2e%2f`, overlong UTF-8, `%00`, `/etc/passwd`, `/proc/self/`, `C:\Windows\...`, `file://` | yes |
| Command injection | a shell separator (`;` `\|` `&&`) followed by a command (`; cat /etc/passwd`, `\| whoami`), `$(cmd)`, backticks, `${IFS}`, reverse shells (`nc -e`, `/dev/tcp/`), `powershell -enc` | yes |
| Log4Shell | `${jndi:ldap://...}`, nested-lookup obfuscation (`${${lower:j}ndi:...}`, `${${::-j}...}`), `${env:...}`, `${sys:...}` | yes |
| NoSQL injection | operator keys and objects (`{"$ne":null}`, `user[$gt]=`), `$where` JavaScript, `db.users.find(`, `' \|\| '1'=='1` | yes |
| SSRF | URLs that point at loopback, private ranges, link-local or cloud metadata (`169.254.169.254`), decimal/hex/octal IPs, `user@127.0.0.1`, `gopher://`/`dict://` | **no**: browsers send `Origin: http://localhost:5173` and `Referer` headers normally |

**Fast by construction.** Each value is normalised once and shared by all detectors, and every regex is gated by a cheap `indexOf` check for a literal any match must contain (`..` for path traversal, `union` for UNION SELECT, `;` `\|` `&&` for the shell patterns). Normal text rarely contains those, so most regexes never run: on a 1.4 KB body this cut detection from about 850 µs to about 14 µs, with identical results on the whole test corpus.

### Monitor mode: detect without blocking

Switching on a WAF against real traffic usually blocks something legitimate. Monitor mode is how you find out first:

```properties
securegate.mode=MONITOR      # or set SECUREGATE_MODE=MONITOR in .env
```

| | `ENFORCE` (default) | `MONITOR` |
|---|---|---|
| Attack detected | 400, alert `"action":"BLOCKED"`, counts toward auto-block | **passes through**, alert `"action":"DETECTED"` |
| Rate limit exceeded | 429 | passes through, alert `DETECTED` |
| Body over the size limit | 400 | passes through, intact, alert `DETECTED` |
| Automatic IP blocks | created after repeated violations | **never created** |
| IPs already blocked, or blocked by an admin | 403 | still 403 |

Run in monitor mode for a few days, open the dashboard, look at everything marked **Detected (not blocked)**, add [path exclusions](#path-exclusions) for the false positives, then switch to enforce.

You can switch at runtime without a restart, from the dashboard's **Mode** button or the API (the change lasts until the next restart; set `securegate.mode` to make it permanent):

```bash
curl -s -X PUT http://localhost:8080/admin/mode -H "X-Admin-Token: change-me" -H "Content-Type: application/json" -d '{"mode":"MONITOR"}'
```

### Security response headers

`SecurityHeadersFilter` adds these to **every** response, including the 400/403/429 that SecureGate produces itself (OWASP A05 Security Misconfiguration):

| Header | Default | Setting |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | always |
| `X-Frame-Options` | `DENY` | `securegate.headers.frame-options` |
| `Referrer-Policy` | `no-referrer` | `securegate.headers.referrer-policy` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | `securegate.headers.permissions-policy` |
| `Cross-Origin-Opener-Policy` | `same-origin` | `securegate.headers.cross-origin-opener-policy` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`, **HTTPS only** (also via `X-Forwarded-Proto: https` when `trust-forwarded-for=true`) | `securegate.headers.hsts-max-age-seconds` (`0` disables) |
| `Content-Security-Policy` | none for your app's pages (a wrong CSP breaks sites), **strict for `/admin` and `/dashboard`** | `securegate.headers.content-security-policy` |

* **Your app's own headers win.** In embedded mode the app can override any of them. In gateway mode a header the upstream sends replaces SecureGate's instead of being duplicated.
* Set `securegate.headers.enabled=false` to turn the whole filter off.
* The dashboard's CSP is `default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. It works because the dashboard has no inline script or style. Even if a malicious payload in an alert were ever rendered as HTML, the browser would refuse to run it.

**Body size.** The body limit applies twice:

* A request whose `Content-Length` is too large is rejected before its body is read.
* For chunked bodies, at most `max-body-size + 1` bytes are read.

The body is cached, so controllers can still read it after the filter has.

### Rate limiting: sliding window log

Each IP keeps the timestamps of its accepted requests from the last `window-seconds`. A new request is allowed only while fewer than `max-requests` timestamps are in the window.

Unlike a fixed window, this doesn't let a client send 2× the limit across a window boundary. Rejected requests aren't counted, so a client that backs off recovers on its own. Every 429 response includes a `Retry-After` header. Idle IPs are dropped every minute.

### Automatic IP blocking

Every 400 (attack detected) and every 429 (rate limit) counts as one violation against the client IP. (In [monitor mode](#monitor-mode-detect-without-blocking) nothing is counted and nothing is blocked.) When an IP reaches `max-violations` within `violation-window-seconds`:

* the IP is blocked for `block-duration-seconds` (set it to `0` to block until someone unblocks it manually)
* an alert with `"action":"IP_BLOCKED"` is logged

Requests that carry a valid admin token skip the IP block and the rate limit. This way an operator can still call the unblock endpoint after their own IP got blocked during testing.

---

## Configuration

The demo's values live in `src/main/resources/application-demo.yml`. In your own app, set them in `application.properties` or `application.yml`.

| Property | Default | Meaning |
|---|---|---|
| `securegate.enabled` | `true` | Turns the whole middleware on or off |
| `securegate.max-body-size` | `10240` | Maximum body size in bytes (10 KB) |
| `securegate.rate-limit.max-requests` | `100` | Requests allowed per window |
| `securegate.rate-limit.window-seconds` | `60` | Length of the sliding window |
| `securegate.blocking.max-violations` | `5` | Violations that trigger an automatic block |
| `securegate.blocking.violation-window-seconds` | `600` | Window for counting violations (10 min) |
| `securegate.blocking.block-duration-seconds` | `3600` | How long a block lasts (`0` = permanent) |
| `securegate.blocking.whitelist` | `[]` | IPs that are never rate-limited or blocked |
| `securegate.admin.token` | `${SECUREGATE_ADMIN_TOKEN:change-me}` | Token required in the `X-Admin-Token` header |
| `securegate.trust-forwarded-for` | `false` | Use `X-Forwarded-For` as the client IP. Turn on only behind a proxy you control, because clients can forge this header. |
| `securegate.mode` | `ENFORCE` | `ENFORCE` blocks attacks, `MONITOR` only logs them as `DETECTED`. Switchable at runtime. Env var: `SECUREGATE_MODE`. See [Monitor mode](#monitor-mode-detect-without-blocking). |
| `securegate.headers.enabled` | `true` | Add security headers to every response. See [Security response headers](#security-response-headers). |
| `securegate.headers.frame-options` | `DENY` | `X-Frame-Options` value (empty = don't send) |
| `securegate.headers.referrer-policy` | `no-referrer` | `Referrer-Policy` value |
| `securegate.headers.permissions-policy` | `camera=(), microphone=(), geolocation=()` | `Permissions-Policy` value |
| `securegate.headers.cross-origin-opener-policy` | `same-origin` | `Cross-Origin-Opener-Policy` value |
| `securegate.headers.hsts-max-age-seconds` | `31536000` | HSTS lifetime, sent on HTTPS only. `0` disables it. |
| `securegate.headers.content-security-policy` | *(empty)* | CSP for your app's responses. Empty = none. |
| `securegate.excluded-paths` | `[]` | Ant-style patterns that skip SecureGate entirely. See [Path exclusions](#path-exclusions). |
| `securegate.detection.exclusions` | `[]` | Patterns where some or all detectors are skipped. See [Path exclusions](#path-exclusions). |
| `securegate.alerts.log-file` | `logs/alerts.json` | Path of the alert log |
| `securegate.alerts.max-payload-length` | `500` | Logged payloads are truncated to this many characters |
| `securegate.proxy.target-url` | *(empty)* | **Gateway mode.** The upstream app's base URL (`http://app:3000`). Leave empty for embedded mode. Env var: `SECUREGATE_PROXY_TARGETURL`. |
| `securegate.proxy.connect-timeout-ms` | `5000` | Timeout for connecting to the upstream |
| `securegate.proxy.read-timeout-ms` | `30000` | Maximum wait for the upstream response, then 504 |
| `securegate.proxy.rewrite-redirects` | `true` | Rewrite upstream `Location` headers that point at `target-url` into relative paths |

Any property can be overridden with an environment variable. For example, add `-e SECUREGATE_RATELIMIT_MAXREQUESTS=20` to `docker run`.

---

## Embedded mode: use SecureGate inside a Spring Boot app

Prefer [gateway mode](#gateway-mode-protect-any-app) unless you specifically want SecureGate inside the app process. For example, embedded mode means one less service to run.

**Requirements:** Spring Boot 3.x (`jakarta.*` servlet API), Java 17+ and a servlet web app (`spring-boot-starter-web`). WebFlux apps are not supported.

### 1. Install the library into your local Maven repository

From this project's folder (no Maven install needed, the wrapper downloads it):

```bash
mvnw.cmd install -DskipTests
```

On macOS or Linux, run `./mvnw install -DskipTests`. This puts `com.securegate:securegate:1.0.0` in `~/.m2/repository`.

### 2. Add the dependency to your app's `pom.xml`

```xml
<dependency>
  <groupId>com.securegate</groupId>
  <artifactId>securegate</artifactId>
  <version>1.0.0</version>
</dependency>
```

With Gradle, add `mavenLocal()` to `repositories` and `implementation 'com.securegate:securegate:1.0.0'`.

### 3. Configure it (optional) in your `application.properties`

```properties
securegate.admin.token=${SECUREGATE_ADMIN_TOKEN}
securegate.rate-limit.max-requests=100
securegate.blocking.max-violations=5
securegate.alerts.log-file=logs/alerts.json
```

Every setting has a default, so this step is optional. **Do set your own admin token.**

### 4. Run your app

That's it. No annotation, `@Import` or code change is needed. SecureGate is a Spring Boot **auto-configuration**: `META-INF/spring/...AutoConfiguration.imports` points to `SecurityFilterConfig`, which registers the following automatically:

* The 4 filters, on `/*`, ahead of your own filters and Spring Security
* The services (rate limiter, IP blocking, alert logger)
* `/admin/alerts`, `/admin/blocked-ips` and `/admin/config`
* The dashboard at `/dashboard`

What stays out of your app:

* **The vulnerable `/api/*` demo endpoints** only exist under the `demo` profile, which only SecureGate's own launcher activates.
* **The demo's `application-demo.yml`** is profile-specific too, so it never overrides your settings.

### Tested integration

This was verified with a separate `com.example.shop` app that has `/products?name=` and `POST /reviews` endpoints and the properties above:

| Check | Result |
|---|---|
| `GET /products?name=laptop` | 200, reaches the app's controller |
| `GET /products?name=' OR 1=1 --` | 400 `SQLi detected` |
| `POST /reviews {"text":"<script>…"}` | 400 `XSS detected` |
| `POST /reviews {"text":"Great laptop"}` | 200, the app's controller still reads the body |
| `GET /api/search` (demo endpoint) | 404, not exposed |
| `/admin/*` with the default `change-me` token | 401, the app's own token is enforced |
| Requests over the app's 20/min limit | 429, then 403 after 5 violations |
| `logs/shop-alerts.json` | Written to the configured path |

### Customising

* **Turn it off** in an environment with `securegate.enabled=false`.
* **Replace a service.** The services are `@ConditionalOnMissingBean`, so defining your own `RateLimiterService`, `IpBlockingService` or `AlertLoggerService` bean replaces the default (for example, a Redis-backed rate limiter).
* **Add a detector.** Any extra `AttackDetector` bean (for example, a command-injection detector) is picked up by the detection filter automatically.
* **Behind a load balancer or reverse proxy,** set `securegate.trust-forwarded-for=true`. Otherwise every client appears to have the proxy's IP, and the proxy itself gets rate-limited and blocked.
* **Endpoints that legitimately accept HTML or SQL-like text** (a rich-text editor, a code snippet field) would trigger the detectors. Use [path exclusions](#path-exclusions) to turn off just the detector that gets in the way.

### Path exclusions

There are two kinds of exclusion:

```yaml
securegate:
  # 1. Full bypass: no IP blocking, no rate limit, no attack detection.
  #    For health checks, metrics scrapers and similar machine traffic.
  excluded-paths:
    - /actuator/health/**
    - /actuator/prometheus

  # 2. Per-detector: switch off only the detectors that cause false positives.
  #    The body-size limit, rate limiting and IP blocking still apply.
  detection:
    exclusions:
      - paths: [/api/editor/**, /api/posts/*/body]
        types: [XSS]                    # rich-text editor sends HTML
      - paths: [/api/sql-console]
        types: [SQLI]                   # admin tool that accepts SQL
      - paths: [/api/import]            # no types → skip all seven detectors (not the size limit)
      - paths: [/api/fetch-preview]
        types: [SSRF]                   # a "fetch this URL" feature that legitimately takes http://localhost URLs
```

In `application.properties` form:

```properties
securegate.excluded-paths[0]=/actuator/health/**
securegate.detection.exclusions[0].paths[0]=/api/editor/**
securegate.detection.exclusions[0].types[0]=XSS
```

How the rules work:

* **Patterns are Ant-style.** `*` matches one path segment and `**` matches any number of segments.
* **Matching uses the canonical path,** meaning the path after decoding `%XX`, removing `;params`, collapsing `//` and resolving `.` and `..`, which is the same path Tomcat routes. So `/public/../api/users` is checked as `/api/users` and can't borrow the exclusion for `/public/**`.
* **Exclusions never switch off admin authentication.** Even `excluded-paths: [/**]` leaves `/admin/**` token-protected.
* **The body-size limit can't be excluded.** `types` accepts only `SQLI`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`, `SSRF`, `LOG4SHELL` and `NOSQLI`.
* **Bad config stops the app at startup.** A pattern that doesn't start with `/`, or an unknown type, fails with a clear message. SecureGate never starts with a silently ignored rule.
* **Check what's active** with `GET /admin/config`. It lists the exclusions in effect, and the startup log prints a warning for every full-bypass pattern.

Exclusions are a trade-off. A path with XSS detection off relies entirely on your app's own output encoding for that input. Keep the patterns as narrow as you can.

---

## Demo endpoints (intentionally unprotected)

| Endpoint | Target for |
|---|---|
| `GET /api/search?q=...` | SQLi and XSS. Echoes `q` into a string-built SQL query. |
| `GET /api/file?path=...` | Path traversal. Echoes the path joined to `/var/app/files/`. |
| `POST /api/comment` with body `{"text":"..."}` | XSS in the body. Echoes `text` back as raw HTML. |

These endpoints only *simulate* unsafe behaviour. They never touch a real database or the filesystem.

---

## Curl examples

The examples assume the container is running on `localhost:8080`.

Use `-G --data-urlencode` for query-string payloads. Tomcat itself rejects raw `<`, `>` and spaces in a URL before any filter runs, so the payload has to be encoded to reach SecureGate.

> The default limit is 5 violations. The five attacks below therefore get *your own IP* blocked on the fifth one, which also shows auto-blocking working. To unblock yourself, see the [admin endpoints](#admin-endpoints).

### 1. SQL injection: `GET /api/search`

```bash
curl -i -G http://localhost:8080/api/search --data-urlencode "q=' OR 1=1 --"
```

```http
HTTP/1.1 400
Content-Type: application/json;charset=UTF-8

{"blocked":true,"reason":"SQLi detected","timestamp":"2026-11-18T11:08:02.093321400Z"}
```

### 2. XSS in a query parameter: `GET /api/search`

```bash
curl -i -G http://localhost:8080/api/search --data-urlencode "q=<script>alert(1)</script>"
```

```http
HTTP/1.1 400

{"blocked":true,"reason":"XSS detected","timestamp":"2026-11-18T11:08:02.164003Z"}
```

### 3. Path traversal (encoded `..%2F`): `GET /api/file`

```bash
curl -i "http://localhost:8080/api/file?path=..%2F..%2Fetc%2Fpasswd"
```

```http
HTTP/1.1 400

{"blocked":true,"reason":"Path traversal detected","timestamp":"2026-11-18T11:08:02.229498600Z"}
```

### 4. XSS in a JSON body: `POST /api/comment`

```bash
curl -i -X POST http://localhost:8080/api/comment -H "Content-Type: application/json" -d '{"text":"<img src=x onerror=alert(1)>"}'
```

```http
HTTP/1.1 400

{"blocked":true,"reason":"XSS detected","timestamp":"2026-11-18T11:08:02.336360700Z"}
```

### 5. Oversized payload (> 10 KB): `POST /api/comment`

```bash
printf '{"text":"%s"}' "$(head -c 12000 /dev/zero | tr '\0' a)" | curl -i -X POST http://localhost:8080/api/comment -H "Content-Type: application/json" --data-binary @-
```

```http
HTTP/1.1 400

{"blocked":true,"reason":"Payload too large","timestamp":"2026-11-18T11:08:02.494081100Z"}
```

That was the 5th violation, so the IP is now blocked. Any further request from it gets a 403, even a harmless one:

```bash
curl -i -G http://localhost:8080/api/search --data-urlencode "q=laptop"
```

```http
HTTP/1.1 403

{"blocked":true,"reason":"IP address is blocked","timestamp":"2026-11-18T11:08:02.569315700Z"}
```

### Rate limit (HTTP 429)

On a freshly started container, request 101 within a minute is rejected:

```bash
for i in $(seq 1 101); do curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/api/search?q=hi"; done | sort | uniq -c
```

```
    100 200
      1 429
```

The 429 response body is `{"blocked":true,"reason":"Rate limit exceeded",...}` and it carries a `Retry-After` header.

### 6. `/admin/alerts` after the attacks

```bash
curl -s http://localhost:8080/admin/alerts -H "X-Admin-Token: change-me"
```

```json
{
  "count" : 7,
  "alerts" : [ {
    "timestamp" : "2026-11-18T11:08:02.569315700Z",
    "ip" : "172.17.0.1",
    "attack_type" : "BLOCKED_IP",
    "endpoint" : "/api/search",
    "payload" : "GET /api/search",
    "action" : "BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.492809300Z",
    "ip" : "172.17.0.1",
    "attack_type" : "OVERSIZED_PAYLOAD",
    "endpoint" : "/api/comment",
    "payload" : "IP auto-blocked after repeated violations",
    "action" : "IP_BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.487352600Z",
    "ip" : "172.17.0.1",
    "attack_type" : "OVERSIZED_PAYLOAD",
    "endpoint" : "/api/comment",
    "payload" : "Content-Length=12011 (max 10240)",
    "action" : "BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.335359700Z",
    "ip" : "172.17.0.1",
    "attack_type" : "XSS",
    "endpoint" : "/api/comment",
    "payload" : "body.text=<img src=x onerror=alert(1)>",
    "action" : "BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.228493Z",
    "ip" : "172.17.0.1",
    "attack_type" : "PATH_TRAVERSAL",
    "endpoint" : "/api/file",
    "payload" : "param:path=../../etc/passwd",
    "action" : "BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.163000400Z",
    "ip" : "172.17.0.1",
    "attack_type" : "XSS",
    "endpoint" : "/api/search",
    "payload" : "param:q=<script>alert(1)</script>",
    "action" : "BLOCKED"
  }, {
    "timestamp" : "2026-11-18T11:08:02.047038400Z",
    "ip" : "172.17.0.1",
    "attack_type" : "SQLi",
    "endpoint" : "/api/search",
    "payload" : "param:q=' OR 1=1 --",
    "action" : "BLOCKED"
  } ]
}
```

The same entries are in `logs/alerts.json`, one per line:

```json
{"timestamp":"2026-11-18T11:08:02.047038400Z","ip":"172.17.0.1","attack_type":"SQLi","endpoint":"/api/search","payload":"param:q=' OR 1=1 --","action":"BLOCKED"}
```

Possible `action` values:

* `BLOCKED`: the request was rejected with 400, 403 or 429.
* `IP_BLOCKED`: this request caused the IP to be auto-blocked.

---

## Admin endpoints

> **Security fix (path canonicalisation).** Earlier builds matched `/admin` against the raw request URI, so `/%61dmin/config` and `/admin;x=1/config` reached admin endpoints without a token, because Tomcat decodes and strips those before routing. All path decisions now use the canonical path, and the admin prefix is matched case-insensitively. Regression tests cover `%61`, `;params`, `//`, `/./` and upper-case variants. If you deployed an earlier build, rotate your admin token.

Every admin endpoint requires the header `X-Admin-Token: <token>`. A request without a valid token gets a 401.

| Method & path | Description |
|---|---|
| `GET /admin/alerts` | The last 50 alerts, newest first. Use `?limit=n` for a different count (max 500). |
| `GET /admin/blocked-ips` | IPs that are currently blocked, with reason and expiry |
| `POST /admin/blocked-ips` | Block an IP manually. Body: `{"ip":"1.2.3.4","reason":"optional"}`. Manual blocks last `block-duration-seconds` like automatic ones. |
| `DELETE /admin/blocked-ips/{ip}` | Unblock an IP manually (returns 404 if the IP wasn't blocked) |
| `GET /admin/config` | The active limits and exclusions, the deployment mode (`embedded`/`gateway`), the enforcement mode, plus the caller's IP and its current violation count |
| `GET /admin/mode` | The enforcement mode: `{"enforcement":"ENFORCE"}` |
| `PUT /admin/mode` | Switch at runtime. Body: `{"mode":"MONITOR"}` or `{"mode":"ENFORCE"}`. Lasts until restart. |

```bash
curl -s http://localhost:8080/admin/blocked-ips -H "X-Admin-Token: change-me"
```

```json
{
  "count" : 1,
  "blocked_ips" : [ {
    "ip" : "172.17.0.1",
    "blocked_at" : "2026-11-18T11:08:02.492809300Z",
    "expires_at" : "2026-11-18T12:08:02.492809300Z",
    "reason" : "Automatic block: 5 violations within 600s (last: OVERSIZED_PAYLOAD)",
    "violation_count" : 5
  } ]
}
```

```bash
curl -s -X DELETE http://localhost:8080/admin/blocked-ips/172.17.0.1 -H "X-Admin-Token: change-me"
```

```json
{ "ip" : "172.17.0.1", "unblocked" : true }
```

> With Docker port publishing, the app sees host requests as coming from the bridge gateway, usually `172.17.0.1`. If you run with `java -jar`, a local client shows up as `0:0:0:0:0:0:0:1` or `127.0.0.1`.

---

## OWASP mapping

The main IDs come from the **OWASP Top 10:2021**. The API-specific risks come from the **OWASP API Security Top 10:2023**.

| Protection | OWASP Top 10:2021 | Also maps to | CWE |
|---|---|---|---|
| SQL injection detection | **A03:2021 – Injection** | A05:2025 Injection | CWE-89 |
| XSS detection | **A03:2021 – Injection** (XSS is part of Injection since 2021) | A05:2025 Injection | CWE-79 |
| Path traversal detection | **A01:2021 – Broken Access Control** | API1:2023 BOLA (file/object access) | CWE-22 |
| Command injection detection | **A03:2021 – Injection** | A05:2025 Injection | CWE-78 |
| NoSQL injection detection | **A03:2021 – Injection** | A05:2025 Injection | CWE-943 |
| SSRF detection | **A10:2021 – Server-Side Request Forgery** | API7:2023 Server Side Request Forgery | CWE-918 |
| Log4Shell / JNDI detection | **A06:2021 – Vulnerable and Outdated Components** (virtual patch for CVE-2021-44228) | A03:2025 Software Supply Chain Failures | CWE-917, CWE-502 |
| Security response headers | **A05:2021 – Security Misconfiguration** | API8:2023 Security Misconfiguration | CWE-693, CWE-1021 (clickjacking), CWE-319 (HSTS) |
| Oversized payload limit | **A04:2021 – Insecure Design** (missing resource limits) | **API4:2023 – Unrestricted Resource Consumption** | CWE-770 |
| Sliding-window rate limiting | **A07:2021 – Identification and Authentication Failures** (brute force, credential stuffing) | **API4:2023 – Unrestricted Resource Consumption** | CWE-307, CWE-799 |
| Automatic IP blocking | **A07:2021 – Identification and Authentication Failures** | API4:2023 | CWE-307 |
| Structured alert log + `/admin/alerts` | **A09:2021 – Security Logging and Monitoring Failures** | A09:2025 Security Logging & Alerting Failures | CWE-778, CWE-117 (log injection prevented via JSON escaping) |
| Token-protected admin API | **A01:2021 – Broken Access Control** | API5:2023 Broken Function Level Authorization | CWE-306 |

References:

* <https://owasp.org/Top10/>
* <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
* [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

## Quality and performance (measured)

Both numbers below come from tests and tools in this repository, so you can rerun them. Both come with caveats, listed under each table.

### Detection quality

`DetectorQualityTest` runs every detector over a generated, deterministic corpus and writes `target/detector-quality.md`.

* **Normal input:** 4,052 inputs: names with apostrophes (`O'Brien`, `L'Hôte`), addresses, product reviews full of SQL-ish English (`select`, `union`, `drop`, `update`, `--`, `1 or 2`), `Tom & Jerry`, `<3`, `a < b`, markdown backticks, URLs, French and Arabic text, plus realistic browser headers (user agents, `Origin: http://localhost:5173`, JWTs, cookies).
* **Attacks:** 122 payloads across the 7 attack types, each tested as written, URL-encoded, double URL-encoded and UPPER-CASE (488 variants).

| Result | |
|---|---|
| False positives | **0 of 4,052** |
| Attacks caught | **488 of 488** (SQLi 100, XSS 80, path traversal 60, command injection 80, SSRF 72, Log4Shell 40, NoSQL 56) |

**Caveats, honestly:**

* **The first run caught 474 of 488 (97.1%).** I then fixed the misses: parenthesised SQL tautologies (`') OR ('1'='1`), double-encoded `%c0%af` and `%00`, Windows `& ipconfig`, and Mongo `'; return true;`. So 100% is partly tuned to this corpus, and 97% is the fairer number for payloads you haven't seen yet.
* **The corpus is synthetic.** It guards against regressions and proves the detectors aren't trigger-happy on tricky text. It says nothing certain about *your* traffic. For that, run [monitor mode](#monitor-mode-detect-without-blocking) first.
* A signature WAF can always be bypassed by an attacker who is willing to try. This is a safety net, not a replacement for parameterised queries and output encoding.

### Performance

[`tools/LoadTest.java`](tools/LoadTest.java) is a dependency-free load tester (`java tools/LoadTest.java <url>`). Measured with 16 concurrent connections, 20,000 requests after a 4,000-request warm-up. Latencies are in milliseconds.

**Embedded mode**: the same demo app with SecureGate off (`--securegate.enabled=false`) and on:

| Request | SecureGate | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|---|
| `GET /api/search?q=laptop` | off | 1.57 | 3.50 | 4.89 | 8,959 req/s |
| | **on** | **1.84** | 4.35 | 6.39 | 7,463 req/s |
| `POST` 1.4 KB JSON body | off | 1.78 | 3.85 | 5.23 | 8,020 req/s |
| | **on** | **1.87** | 5.04 | 7.27 | 6,959 req/s |

Median overhead: **+0.27 ms** for a GET and **+0.09 ms** for a 1.4 KB POST.

**Gateway mode**: a plain app directly vs through SecureGate:

| Request | Path | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|---|
| `GET /products?name=laptop` | direct | 1.30 | 2.66 | 3.81 | 11,066 req/s |
| | **via SecureGate** | **2.94** | 6.51 | 9.37 | 4,596 req/s |
| `POST` 1.4 KB JSON body | direct | 1.32 | 2.74 | 3.76 | 10,833 req/s |
| | **via SecureGate** | **2.44** | 6.30 | 9.32 | 5,388 req/s |

Median overhead: **+1.1 to +1.6 ms**, most of it the extra network hop that a gateway always adds.

**How these numbers got better.** The first measurements showed a 1.4 KB POST costing **+3.0 to +3.9 ms** at the median, and throughput dropping to about 30% of the unprotected app. Profiling showed about 850 µs of regex work per request. Normalising each value once, and gating every regex behind a cheap `indexOf` check, cut that to about 14 µs and lifted the throughput to 87%. The detection results did not change (same 488 of 488, same 0 false positives).

**Caveats, honestly:**

* Everything ran on one Windows machine (12 cores, JDK 21) with the load generator, SecureGate and the app **all on the same machine** over localhost, so absolute numbers will differ in production. Compare the *ratios*, not the raw figures.
* Only normal requests were measured. A blocked attack is cheaper, since it never reaches the app.
* One request shape per row, a tiny app, no database. A real app does far more work per request, which makes SecureGate's share of the latency smaller.
* In gateway mode the hop itself costs more than the inspection. If that matters, use embedded mode.

---

## Tests

```bash
mvnw.cmd test
```

The suite has 261 tests:

* `SqlInjectionDetectorTest`, `XssDetectorTest` and `PathTraversalDetectorTest` feed each detector attack payloads, including URL-encoded, double-encoded, HTML-entity and mixed-case variants. They also check benign input like `O'Reilly`, `rock and roll`, `one=two` and `version 1.2..3` to keep false positives in check.
* `NewDetectorsTest` does the same for command injection, SSRF, Log4Shell and NoSQL injection. Its benign cases include `uname=bob&id=5`, `Tom && Jerry`, `my router is 192.168.1.1`, `Hello ${name}` and `$50.00`.
* `DetectorQualityTest` is the benchmark described above. It **fails the build** if any benign input is flagged or if fewer than 97% of attack variants are caught.
* `MonitorModeIntegrationTest` checks that attacks pass through and are logged as `DETECTED`, no automatic block is ever created, oversized bodies still reach the app intact, rate-limit hits are only logged, the mode can be switched at runtime, and the mode endpoint needs the admin token.
* `SecureGateIntegrationTest` runs the full filter chain through MockMvc. It covers each detection type, header attacks, the 429 response, auto-blocking followed by an admin unblock, manual blocking, the config endpoint, admin authentication, the alert log format, and checks that the dashboard still loads for a blocked IP. It also verifies the security headers (on normal and blocked responses, HSTS only over HTTPS, a strict CSP on `/dashboard` and `/admin`), that the dashboard HTML has no inline script or style, and that `Origin: http://localhost:5173` isn't flagged as SSRF.
* `RequestPathsTest` checks that path canonicalisation matches how Tomcat routes requests (`%61`, `;params`, `//`, `.`/`..`, encoded dots).
* `ExclusionIntegrationTest` covers full bypass, per-detector exclusions, the size limit still applying, raw paths that only *look* excluded, and admin auth surviving an `/admin/**` exclusion.
* `GatewayIntegrationTest` starts a stub upstream server and checks that:
  * clean requests and JSON and form bodies are forwarded intact
  * attacks never reach the upstream
  * the upstream gets the canonical path
  * `X-Forwarded-For` is set and spoofed values are replaced
  * the admin token isn't leaked upstream
  * `/admin` and the dashboard stay local
  * upstream status codes pass through and redirects are rewritten
  * security headers are added, and a header the upstream sets itself replaces ours

## Limitations

* **Signatures are a safety net, not a replacement for secure code.** Keep using parameterised queries, output encoding and canonical path checks in the app itself. Like any WAF, the detectors can be bypassed and can produce false positives. Tune the patterns in `filter/detector/` for your own traffic, and start in [monitor mode](#monitor-mode-detect-without-blocking).
* **Known false-positive areas.** Apps that *legitimately* accept shell-like text, MongoDB operators, `http://localhost` URLs (a "fetch this URL" feature) or `${...}` templates will trigger the matching detector. Use [path exclusions](#path-exclusions) with the narrowest `types` you can.
* **State is per instance.** Rate-limit counters, violation counts and the block list live in memory. They reset on restart and are not shared across replicas.
* **Multipart bodies are only size-checked.** Their content isn't scanned. In gateway mode they're streamed to the upstream.
* **Gateway mode has no WebSocket or Server-Sent-Events streaming support,** and no HTTP/2 to the upstream.
* **SecureGate doesn't terminate TLS.** For HTTPS, put it behind a TLS terminator (Nginx, Traefik, a cloud load balancer) with `trust-forwarded-for=true`, or use Spring Boot's `server.ssl.*` settings. `target-url` itself can be `https://`.
