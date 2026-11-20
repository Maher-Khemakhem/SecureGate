package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import com.securegate.model.AttackType;
import com.securegate.service.AlertLoggerService;
import com.securegate.service.IpBlockingService;
import com.securegate.service.ModeService;
import com.securegate.service.RateLimiterService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Per-IP sliding window rate limiting. Exceeding the limit returns HTTP 429
 * and counts as a violation toward automatic IP blocking.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private final SecurityProperties properties;
    private final RateLimiterService rateLimiter;
    private final IpBlockingService blockingService;
    private final AlertLoggerService alertLogger;

    private final PathExclusions exclusions;
    private final ModeService modeService;

    public RateLimitFilter(SecurityProperties properties, RateLimiterService rateLimiter,
                           IpBlockingService blockingService, AlertLoggerService alertLogger,
                           PathExclusions exclusions, ModeService modeService) {
        this.properties = properties;
        this.rateLimiter = rateLimiter;
        this.blockingService = blockingService;
        this.alertLogger = alertLogger;
        this.exclusions = exclusions;
        this.modeService = modeService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return exclusions.isBypassed(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String ip = SecurityResponses.clientIp(request, properties);
        if (SecurityResponses.isAdmin(request) || SecurityResponses.isDashboardPage(request)
                || blockingService.isWhitelisted(ip)) {
            chain.doFilter(request, response);
            return;
        }
        if (rateLimiter.tryAcquire(ip)) {
            response.setHeader("X-RateLimit-Limit", String.valueOf(properties.getRateLimit().getMaxRequests()));
            chain.doFilter(request, response);
            return;
        }
        String endpoint = SecurityResponses.endpoint(request);
        if (modeService.isMonitor()) {
            // Monitor mode: record that the limit would have been hit, but let the request through.
            alertLogger.log(ip, AttackType.RATE_LIMIT.label(), endpoint,
                    request.getMethod() + " " + endpoint, "DETECTED");
            chain.doFilter(request, response);
            return;
        }
        alertLogger.log(ip, AttackType.RATE_LIMIT.label(), endpoint,
                request.getMethod() + " " + endpoint, "BLOCKED");
        if (blockingService.recordViolation(ip, AttackType.RATE_LIMIT.label())) {
            alertLogger.log(ip, AttackType.RATE_LIMIT.label(), endpoint, "IP auto-blocked after repeated violations",
                    "IP_BLOCKED");
        }
        response.setHeader("Retry-After", String.valueOf(rateLimiter.retryAfterSeconds(ip)));
        SecurityResponses.write(response, 429, AttackType.RATE_LIMIT.reason());
    }
}
