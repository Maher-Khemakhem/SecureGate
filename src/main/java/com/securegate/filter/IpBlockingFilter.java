package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import com.securegate.model.AttackType;
import com.securegate.service.AlertLoggerService;
import com.securegate.service.IpBlockingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * First line of defence: rejects requests from blocked IPs with HTTP 403.
 */
public class IpBlockingFilter extends OncePerRequestFilter {

    private final SecurityProperties properties;
    private final IpBlockingService blockingService;
    private final AlertLoggerService alertLogger;

    private final PathExclusions exclusions;

    public IpBlockingFilter(SecurityProperties properties, IpBlockingService blockingService,
                            AlertLoggerService alertLogger, PathExclusions exclusions) {
        this.properties = properties;
        this.blockingService = blockingService;
        this.alertLogger = alertLogger;
        this.exclusions = exclusions;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return exclusions.isBypassed(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityResponses.isAdmin(request) || SecurityResponses.isDashboardPage(request)) {
            chain.doFilter(request, response);
            return;
        }
        String ip = SecurityResponses.clientIp(request, properties);
        if (blockingService.isBlocked(ip)) {
            alertLogger.log(ip, AttackType.BLOCKED_IP.label(), SecurityResponses.endpoint(request),
                    request.getMethod() + " " + request.getRequestURI(), "BLOCKED");
            SecurityResponses.write(response, HttpServletResponse.SC_FORBIDDEN, AttackType.BLOCKED_IP.reason());
            return;
        }
        chain.doFilter(request, response);
    }
}
