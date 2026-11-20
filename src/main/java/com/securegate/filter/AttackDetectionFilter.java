package com.securegate.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securegate.config.SecurityProperties;
import com.securegate.filter.detector.AttackDetector;
import com.securegate.filter.detector.InputNormalizer;
import com.securegate.model.AttackType;
import com.securegate.service.AlertLoggerService;
import com.securegate.service.IpBlockingService;
import com.securegate.service.ModeService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Inspects URL, query parameters, headers, cookies and body for SQL injection,
 * XSS and path traversal, and enforces a maximum body size. Any hit returns
 * HTTP 400 with a structured JSON error, writes an alert and counts as a
 * violation toward automatic IP blocking.
 */
public class AttackDetectionFilter extends OncePerRequestFilter {

    private static final int MAX_JSON_DEPTH = 32;

    private final SecurityProperties properties;
    private final List<AttackDetector> detectors;
    private final IpBlockingService blockingService;
    private final AlertLoggerService alertLogger;
    private final ObjectMapper mapper = new ObjectMapper();

    private final PathExclusions exclusions;
    private final ModeService modeService;

    public AttackDetectionFilter(SecurityProperties properties, List<AttackDetector> detectors,
                                 IpBlockingService blockingService, AlertLoggerService alertLogger,
                                 PathExclusions exclusions, ModeService modeService) {
        this.properties = properties;
        this.detectors = List.copyOf(detectors);
        this.blockingService = blockingService;
        this.alertLogger = alertLogger;
        this.exclusions = exclusions;
        this.modeService = modeService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return exclusions.isBypassed(request);
    }

    /** A value pulled from the request plus where it came from, for the alert payload. */
    private static final class Inspected {
        private final String location;
        private final String value;
        private String normalized;   // computed once, on first use, then shared by every detector

        Inspected(String location, String value) {
            this.location = location;
            this.value = value;
        }

        String value() {
            return value;
        }

        String normalized() {
            if (normalized == null) {
                normalized = InputNormalizer.normalize(value);
            }
            return normalized;
        }

        String describe() {
            return location + "=" + value;
        }

        boolean isHeaderOrCookie() {
            return location.startsWith("header:") || location.startsWith("cookie:");
        }
    }

    private record Finding(AttackType type, String payload) {
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityResponses.isAdmin(request)) {
            chain.doFilter(request, response);
            return;
        }

        long maxBody = properties.getMaxBodySize();
        long declaredLength = request.getContentLengthLong();
        Finding oversized = null;
        HttpServletRequest effective = request;
        String body = null;

        if (declaredLength > maxBody) {
            oversized = new Finding(AttackType.OVERSIZED_PAYLOAD,
                    "Content-Length=" + declaredLength + " (max " + maxBody + ")");
            if (!report(request, response, oversized)) {
                return;
            }
            // Monitor mode: the body is untouched and passes through as it is, unread.
        } else if (shouldBufferBody(request)) {
            byte[] bytes = request.getInputStream().readNBytes((int) Math.min(Integer.MAX_VALUE - 8, maxBody + 1));
            if (bytes.length > maxBody) {
                oversized = new Finding(AttackType.OVERSIZED_PAYLOAD, "Body exceeds " + maxBody + " bytes");
                if (!report(request, response, oversized)) {
                    return;
                }
                // Monitor mode: replay the bytes already read, then the rest of the stream.
                effective = new PrefixedBodyRequest(request, bytes);
            } else {
                body = new String(bytes, StandardCharsets.UTF_8);
                effective = new CachedBodyHttpServletRequest(request, bytes);
            }
        }

        // The size limit above always applies; per-path exclusions only switch off detectors.
        Set<AttackType> skipped = exclusions.skippedDetectors(request);
        List<AttackDetector> active = skipped.isEmpty()
                ? detectors
                : detectors.stream().filter(d -> !skipped.contains(d.type())).toList();

        Finding finding = active.isEmpty() ? null : inspect(effective, body, active);
        if (finding != null && !report(request, response, finding)) {
            return;
        }
        chain.doFilter(effective, response);
    }

    private Finding inspect(HttpServletRequest request, String body, List<AttackDetector> active) {
        List<Inspected> inputs = new ArrayList<>();

        inputs.add(new Inspected("path", request.getRequestURI()));
        // Decoded parameters first so alerts show readable payloads. For a buffered request
        // this includes form-urlencoded body fields. Otherwise (multipart) only the query
        // string is parsed: asking the container for parameters would consume the
        // multipart stream, which the reverse proxy still has to forward.
        Map<String, String[]> params = request instanceof CachedBodyHttpServletRequest cached
                ? cached.getParameterMap()
                : CachedBodyHttpServletRequest.parseQuery(request.getQueryString(), StandardCharsets.UTF_8);
        for (Map.Entry<String, String[]> e : params.entrySet()) {
            inputs.add(new Inspected("param(name)", e.getKey()));
            for (String v : e.getValue()) {
                inputs.add(new Inspected("param:" + e.getKey(), v));
            }
        }
        // Raw query string catches encodings the container decoded away (e.g. overlong UTF-8).
        if (request.getQueryString() != null) {
            inputs.add(new Inspected("query", request.getQueryString()));
        }
        for (String name : Collections.list(request.getHeaderNames())) {
            if ("cookie".equalsIgnoreCase(name)) {
                continue; // inspected per cookie below to avoid ';' separator false positives
            }
            for (String v : Collections.list(request.getHeaders(name))) {
                inputs.add(new Inspected("header:" + name, v));
            }
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                inputs.add(new Inspected("cookie:" + c.getName(), c.getValue()));
            }
        }
        if (body != null && !body.isEmpty()) {
            collectBody(request.getContentType(), body, inputs);
        }

        for (AttackDetector detector : active) {
            for (Inspected input : inputs) {
                if (!detector.appliesToHeaders() && input.isHeaderOrCookie()) {
                    continue;
                }
                if (detector.detect(input.value(), input.normalized())) {
                    return new Finding(detector.type(), input.describe());
                }
            }
        }
        return null;
    }

    private void collectBody(String contentType, String body, List<Inspected> inputs) {
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json")) {
            try {
                JsonNode root = mapper.readTree(body);
                collectJson(root, "body", inputs, 0);
                return;
            } catch (IOException ignored) {
                // Not valid JSON: fall through and scan the raw text.
            }
        }
        inputs.add(new Inspected("body", body));
    }

    /** Walks JSON so that string values are inspected unescaped and without JSON quoting noise. */
    private void collectJson(JsonNode node, String path, List<Inspected> inputs, int depth) {
        if (node == null || depth > MAX_JSON_DEPTH) {
            return;
        }
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> f = fields.next();
                String childPath = path + "." + f.getKey();
                inputs.add(new Inspected(childPath + "(key)", f.getKey()));
                collectJson(f.getValue(), childPath, inputs, depth + 1);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectJson(node.get(i), path + "[" + i + "]", inputs, depth + 1);
            }
        } else if (node.isTextual()) {
            inputs.add(new Inspected(path, node.asText()));
        }
    }

    /**
     * Records a finding. In ENFORCE mode it answers 400, counts a violation toward auto-blocking
     * and returns false (stop the chain). In MONITOR mode it only logs {@code DETECTED}, counts
     * nothing and returns true (carry on).
     *
     * @return true if the request may continue
     */
    private boolean report(HttpServletRequest request, HttpServletResponse response, Finding finding)
            throws IOException {
        String ip = SecurityResponses.clientIp(request, properties);
        String endpoint = SecurityResponses.endpoint(request);
        String attack = finding.type().label();
        if (modeService.isMonitor()) {
            alertLogger.log(ip, attack, endpoint, finding.payload(), "DETECTED");
            return true;
        }
        alertLogger.log(ip, attack, endpoint, finding.payload(), "BLOCKED");
        if (blockingService.recordViolation(ip, attack)) {
            alertLogger.log(ip, attack, endpoint, "IP auto-blocked after repeated violations", "IP_BLOCKED");
        }
        SecurityResponses.write(response, HttpServletResponse.SC_BAD_REQUEST, finding.type().reason());
        return false;
    }

    /**
     * Everything except multipart is buffered (up to the size limit) so it can be
     * inspected and then replayed to the controller or forwarded upstream. Form
     * fields are parsed from the cached body by {@link CachedBodyHttpServletRequest}.
     * Multipart bodies are left untouched and only size-checked.
     */
    private static boolean shouldBufferBody(HttpServletRequest request) {
        String ct = request.getContentType();
        return ct == null || !ct.toLowerCase(Locale.ROOT).startsWith("multipart/");
    }
}
