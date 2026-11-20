package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;

/**
 * First filter in the chain: sets browser security headers on every response, including the
 * 400/403/429 responses SecureGate itself produces (OWASP A05:2021 Security Misconfiguration).
 * <p>
 * Headers are set before the request proceeds, so an app (embedded mode) can override any of
 * them with {@code setHeader}, and in gateway mode a header sent by the upstream replaces
 * ours (see {@link ReverseProxyFilter}).
 */
public class SecurityHeadersFilter extends OncePerRequestFilter {

    /**
     * CSP for SecureGate's own pages. No inline scripts or styles: the dashboard is served as
     * separate files, so a stored XSS payload in an alert could not execute even if it were rendered.
     */
    static final String OWN_PAGES_CSP = "default-src 'self'; img-src 'self' data:; object-src 'none'; "
            + "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    private final SecurityProperties properties;

    public SecurityHeadersFilter(SecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.getHeaders().isEnabled();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        SecurityProperties.Headers h = properties.getHeaders();
        response.setHeader("X-Content-Type-Options", "nosniff");
        setIfPresent(response, "X-Frame-Options", h.getFrameOptions());
        setIfPresent(response, "Referrer-Policy", h.getReferrerPolicy());
        setIfPresent(response, "Permissions-Policy", h.getPermissionsPolicy());
        setIfPresent(response, "Cross-Origin-Opener-Policy", h.getCrossOriginOpenerPolicy());

        if (h.getHstsMaxAgeSeconds() > 0 && isHttps(request)) {
            response.setHeader("Strict-Transport-Security", "max-age=" + h.getHstsMaxAgeSeconds() + "; includeSubDomains");
        }

        if (isOwnPage(request)) {
            response.setHeader("Content-Security-Policy", OWN_PAGES_CSP);
            response.setHeader("Cache-Control", "no-store");
        } else {
            setIfPresent(response, "Content-Security-Policy", h.getContentSecurityPolicy());
        }
        chain.doFilter(request, response);
    }

    private boolean isHttps(HttpServletRequest request) {
        return request.isSecure()
                || (properties.isTrustForwardedFor() && "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")));
    }

    /** SecureGate's own endpoints: the admin API and the dashboard. */
    private boolean isOwnPage(HttpServletRequest request) {
        String path = RequestPaths.canonical(request).toLowerCase(Locale.ROOT);
        String admin = properties.getAdmin().getPathPrefix().toLowerCase(Locale.ROOT);
        return path.equals(admin) || path.startsWith(admin + "/") || path.equals("/dashboard")
                || path.startsWith("/dashboard/");
    }

    private static void setIfPresent(HttpServletResponse response, String name, String value) {
        if (value != null && !value.isBlank()) {
            response.setHeader(name, value);
        }
    }
}
