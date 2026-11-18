package com.securegate.filter;

import jakarta.servlet.http.HttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Computes the request path the way the servlet container routes it.
 * <p>
 * Every security decision based on the path (admin auth, exclusions,
 * dashboard exemption) must use this canonical form, never the raw
 * {@code getRequestURI()}. Otherwise {@code /%61dmin/x} or {@code /admin;p=1/x}
 * would look like a different path to the filter while Tomcat still routes
 * it to {@code /admin/x}.
 */
public final class RequestPaths {

    private RequestPaths() {
    }

    public static String canonical(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }
        return canonical(uri);
    }

    /**
     * Strips {@code ;path-params}, percent-decodes once (as Tomcat does), collapses
     * repeated slashes and resolves {@code .} and {@code ..} segments. The result
     * always starts with {@code /} and never escapes the root.
     */
    public static String canonical(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return "/";
        }
        String path = rawPath;
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }

        Deque<String> segments = new ArrayDeque<>();
        for (String segment : path.split("/", -1)) {
            int semicolon = segment.indexOf(';');
            if (semicolon >= 0) {
                segment = segment.substring(0, semicolon);
            }
            segment = percentDecode(segment);
            if (segment.isEmpty() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                segments.pollLast();
                continue;
            }
            segments.addLast(segment);
        }

        StringBuilder sb = new StringBuilder();
        for (String s : segments) {
            sb.append('/').append(s);
        }
        boolean trailingSlash = path.endsWith("/") && !segments.isEmpty();
        if (sb.length() == 0) {
            return "/";
        }
        return trailingSlash ? sb.append('/').toString() : sb.toString();
    }

    /** Decodes %XX escapes as UTF-8; '+' stays literal (it only means space in query strings). */
    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
            out.write(bytes, 0, bytes.length);
        }
        return out.toString(StandardCharsets.UTF_8);
    }
}
