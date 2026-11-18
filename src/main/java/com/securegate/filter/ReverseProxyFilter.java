package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Gateway mode: the last filter in the chain. Every request that got past IP
 * blocking, rate limiting and attack detection is forwarded to the upstream app
 * at {@code securegate.proxy.target-url}, and the upstream response is streamed
 * back. SecureGate's own /admin API and /dashboard are served locally.
 * <p>
 * The upstream receives the <em>canonical</em> path (the one SecureGate inspected),
 * re-encoded, so it cannot interpret the URL differently from what was checked.
 */
public class ReverseProxyFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ReverseProxyFilter.class);

    /** Connection-level headers that must not be forwarded (RFC 9110 §7.6.1) or that HttpClient sets itself. */
    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
            "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host", "content-length", "expect",
            "http2-settings");

    /** Request headers SecureGate replaces or never leaks upstream. */
    private static final Set<String> STRIP_REQUEST = Set.of(
            AdminAuthFilter.HEADER.toLowerCase(Locale.ROOT), "forwarded", "x-forwarded-for", "x-forwarded-host",
            "x-forwarded-proto", "x-forwarded-port", "x-real-ip");

    /** Response headers the servlet container sets itself. */
    private static final Set<String> STRIP_RESPONSE = Set.of("date");

    private final SecurityProperties properties;
    private final String target;
    private final HttpClient client;
    private final Duration readTimeout;

    public ReverseProxyFilter(SecurityProperties properties) {
        this.properties = properties;
        String url = properties.getProxy().getTargetUrl().trim();
        URI parsed = URI.create(url);
        if (parsed.getScheme() == null || parsed.getHost() == null
                || !(parsed.getScheme().equals("http") || parsed.getScheme().equals("https"))) {
            throw new IllegalStateException("securegate.proxy.target-url must be an absolute http(s) URL, got: " + url);
        }
        this.target = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        this.readTimeout = Duration.ofMillis(properties.getProxy().getReadTimeoutMs());
        this.client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofMillis(properties.getProxy().getConnectTimeoutMs()))
                .build();
        log.info("SecureGate gateway mode: forwarding allowed requests to {}", target);
    }

    public String getTarget() {
        return target;
    }

    /** SecureGate's own endpoints are never proxied. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = RequestPaths.canonical(request);
        String lower = path.toLowerCase(Locale.ROOT);
        String admin = properties.getAdmin().getPathPrefix().toLowerCase(Locale.ROOT);
        return lower.equals(admin) || lower.startsWith(admin + "/")
                || path.equals("/dashboard") || path.equals("/dashboard/") || path.equals("/dashboard/index.html");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        URI uri;
        try {
            uri = upstreamUri(request);
        } catch (IllegalArgumentException e) {
            SecurityResponses.write(response, HttpServletResponse.SC_BAD_REQUEST, "Malformed request URL");
            return;
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(readTimeout);
        copyRequestHeaders(request, builder);
        addForwardingHeaders(request, builder);
        builder.method(request.getMethod(), bodyPublisher(request));

        HttpResponse<InputStream> upstream;
        try {
            upstream = client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            log.warn("Upstream timeout for {} {}", request.getMethod(), uri);
            gatewayError(response, HttpServletResponse.SC_GATEWAY_TIMEOUT, "Upstream timed out");
            return;
        } catch (ConnectException e) {
            log.warn("Upstream {} unreachable: {}", target, e.getMessage());
            gatewayError(response, HttpServletResponse.SC_BAD_GATEWAY, "Upstream unreachable");
            return;
        } catch (IOException | UncheckedIOException e) {
            log.warn("Upstream error for {} {}: {}", request.getMethod(), uri, e.toString());
            gatewayError(response, HttpServletResponse.SC_BAD_GATEWAY, "Upstream error");
            return;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            gatewayError(response, HttpServletResponse.SC_BAD_GATEWAY, "Upstream request interrupted");
            return;
        }

        response.setStatus(upstream.statusCode());
        copyResponseHeaders(upstream, response);
        try (InputStream in = upstream.body()) {
            OutputStream out = response.getOutputStream();
            in.transferTo(out);
            out.flush();
        }
    }

    // ---------------------------------------------------------------- request

    URI upstreamUri(HttpServletRequest request) {
        String path = RequestPaths.canonical(request);
        StringBuilder sb = new StringBuilder(target);
        String[] segments = path.split("/", -1);
        for (int i = 1; i < segments.length; i++) {
            sb.append('/').append(encodeSegment(segments[i]));
        }
        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) {
            sb.append('?').append(query);
        }
        return URI.create(sb.toString());
    }

    private static void copyRequestHeaders(HttpServletRequest request, HttpRequest.Builder builder) {
        for (String name : Collections.list(request.getHeaderNames())) {
            String lower = name.toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(lower) || STRIP_REQUEST.contains(lower)) {
                continue;
            }
            for (String value : Collections.list(request.getHeaders(name))) {
                try {
                    builder.header(name, value);
                } catch (IllegalArgumentException e) {
                    log.debug("Dropping header {} that HttpClient refuses", name);
                }
            }
        }
    }

    private void addForwardingHeaders(HttpServletRequest request, HttpRequest.Builder builder) {
        String clientIp = SecurityResponses.clientIp(request, properties);
        String remote = request.getRemoteAddr();
        String existing = request.getHeader("X-Forwarded-For");
        // Only extend an incoming X-Forwarded-For chain if we trust the hop in front of us.
        String xff = properties.isTrustForwardedFor() && existing != null && !existing.isBlank()
                ? existing + ", " + remote
                : remote;
        builder.header("X-Forwarded-For", xff);
        builder.header("X-Real-IP", clientIp);
        builder.header("X-Forwarded-Proto", request.getScheme());
        builder.header("X-Forwarded-Port", String.valueOf(request.getServerPort()));
        String host = request.getHeader("Host");
        if (host != null) {
            builder.header("X-Forwarded-Host", host);
        }
    }

    private static HttpRequest.BodyPublisher bodyPublisher(HttpServletRequest request) {
        CachedBodyHttpServletRequest cached = unwrap(request);
        if (cached != null) {
            byte[] body = cached.getBody();
            return body.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body);
        }
        boolean hasBody = request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null;
        if (!hasBody) {
            return HttpRequest.BodyPublishers.noBody();
        }
        // Not buffered (multipart): stream it through. Size was already checked by AttackDetectionFilter.
        return HttpRequest.BodyPublishers.ofInputStream(() -> {
            try {
                return request.getInputStream();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    private static CachedBodyHttpServletRequest unwrap(ServletRequest request) {
        ServletRequest current = request;
        while (current != null) {
            if (current instanceof CachedBodyHttpServletRequest cached) {
                return cached;
            }
            current = current instanceof ServletRequestWrapper w ? w.getRequest() : null;
        }
        return null;
    }

    // ---------------------------------------------------------------- response

    private void copyResponseHeaders(HttpResponse<?> upstream, HttpServletResponse response) {
        for (Map.Entry<String, List<String>> header : upstream.headers().map().entrySet()) {
            String name = header.getKey();
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.startsWith(":") || STRIP_RESPONSE.contains(lower)
                    || (HOP_BY_HOP.contains(lower) && !lower.equals("content-length"))) {
                continue;
            }
            for (String value : header.getValue()) {
                if (lower.equals("location")) {
                    value = rewriteLocation(value);
                }
                response.addHeader(name, value);
            }
        }
    }

    /** Turns {@code http://upstream:8081/next} into {@code /next} so clients never see the internal host. */
    private String rewriteLocation(String location) {
        if (properties.getProxy().isRewriteRedirects() && location.startsWith(target)) {
            String rest = location.substring(target.length());
            return rest.isEmpty() ? "/" : rest;
        }
        return location;
    }

    private static void gatewayError(HttpServletResponse response, int status, String reason) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        String body = "{\"blocked\":false,\"error\":\"" + reason + "\",\"timestamp\":\"" + Instant.now() + "\"}";
        response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------------- encoding

    private static final String SEGMENT_SAFE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,=:@";

    /** Percent-encodes a decoded path segment; '/', '?', '#', ';' and '%' are always encoded. */
    static String encodeSegment(String segment) {
        StringBuilder sb = new StringBuilder(segment.length());
        for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            if (b >= 0 && SEGMENT_SAFE.indexOf(c) >= 0) {
                sb.append(c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
            }
        }
        return sb.toString();
    }
}
