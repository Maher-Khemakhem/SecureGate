package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Protects the admin API with a shared token sent in {@code X-Admin-Token}.
 * <p>
 * Requests with a valid token are marked as admin so the IP-block and
 * rate-limit filters let them through. This keeps operators from locking
 * themselves out after their own IP gets blocked during testing.
 */
public class AdminAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Admin-Token";

    private final SecurityProperties properties;

    public AdminAuthFilter(SecurityProperties properties) {
        this.properties = properties;
    }

    /**
     * Uses the canonical path (decoded, path params stripped, dot segments resolved),
     * compared case-insensitively, so encoding tricks like {@code /%61dmin} or
     * {@code /admin;x=1/...} cannot reach admin endpoints without the token.
     * Path exclusions deliberately do not apply here.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String prefix = properties.getAdmin().getPathPrefix().toLowerCase(Locale.ROOT);
        String path = RequestPaths.canonical(request).toLowerCase(Locale.ROOT);
        return !(path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String expected = properties.getAdmin().getToken();
        String provided = request.getHeader(HEADER);
        if (expected == null || expected.isBlank() || provided == null || !constantTimeEquals(expected, provided)) {
            SecurityResponses.write(response, HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid admin token");
            return;
        }
        request.setAttribute(SecurityResponses.ADMIN_AUTHENTICATED, Boolean.TRUE);
        chain.doFilter(request, response);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
