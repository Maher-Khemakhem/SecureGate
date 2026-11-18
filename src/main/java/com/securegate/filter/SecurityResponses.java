package com.securegate.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securegate.config.SecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shared helpers for SecureGate filters: client IP resolution and the
 * structured JSON error body {@code {"blocked":true,"reason":"...","timestamp":"..."}}.
 */
public final class SecurityResponses {

    /** Request attribute set when a request carries a valid admin token. */
    public static final String ADMIN_AUTHENTICATED = "securegate.adminAuthenticated";
    /** Request attribute holding the resolved client IP. */
    public static final String CLIENT_IP = "securegate.clientIp";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityResponses() {
    }

    public static void write(HttpServletResponse response, int status, String reason) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("blocked", true);
        body.put("reason", reason);
        body.put("timestamp", Instant.now().toString());
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        MAPPER.writeValue(response.getOutputStream(), body);
    }

    public static String clientIp(HttpServletRequest request, SecurityProperties properties) {
        Object cached = request.getAttribute(CLIENT_IP);
        if (cached instanceof String ip) {
            return ip;
        }
        String ip = request.getRemoteAddr();
        if (properties.isTrustForwardedFor()) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                ip = forwarded.split(",")[0].trim();
            }
        }
        request.setAttribute(CLIENT_IP, ip);
        return ip;
    }

    public static boolean isAdmin(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(ADMIN_AUTHENTICATED));
    }

    /**
     * The dashboard's static page stays reachable from a blocked or rate-limited IP,
     * otherwise an operator who tests attacks from their own machine could not load
     * the UI to unblock themselves. Its data calls go through the token-protected API.
     */
    public static boolean isDashboardPage(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod()) && !"HEAD".equals(request.getMethod())) {
            return false;
        }
        String path = RequestPaths.canonical(request);
        return path.equals("/dashboard") || path.equals("/dashboard/") || path.equals("/dashboard/index.html")
                || path.equals("/favicon.ico");
    }

    public static String endpoint(HttpServletRequest request) {
        return request.getRequestURI();
    }
}
