package com.securegate.config;

import com.securegate.model.AttackType;
import com.securegate.model.EnforcementMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * All SecureGate settings, bound from the {@code securegate.*} namespace.
 */
@ConfigurationProperties(prefix = "securegate")
public class SecurityProperties {

    /** Master switch for the whole filter chain. */
    private boolean enabled = true;

    /** Maximum accepted request body size in bytes. */
    private long maxBodySize = 10 * 1024;

    /** Use the first X-Forwarded-For hop as client IP (only behind a trusted proxy). */
    private boolean trustForwardedFor = false;

    /**
     * Ant-style path patterns (e.g. {@code /actuator/health/**}) that bypass IP blocking,
     * rate limiting and attack detection entirely. Admin authentication still applies.
     */
    private List<String> excludedPaths = new ArrayList<>();

    /** ENFORCE blocks attacks. MONITOR only logs them ("action":"DETECTED"). Switchable at runtime. */
    private EnforcementMode mode = EnforcementMode.ENFORCE;

    private final Headers headers = new Headers();
    private final Detection detection = new Detection();
    private final Proxy proxy = new Proxy();
    private final Admin admin = new Admin();
    private final RateLimit rateLimit = new RateLimit();
    private final Blocking blocking = new Blocking();
    private final Alerts alerts = new Alerts();

    /**
     * Security headers added to every response. A header the protected app sets itself
     * always wins. SecureGate's own pages (/dashboard, /admin) always get a strict CSP.
     */
    public static class Headers {
        private boolean enabled = true;
        private String frameOptions = "DENY";
        private String referrerPolicy = "no-referrer";
        private String permissionsPolicy = "camera=(), microphone=(), geolocation=()";
        private String crossOriginOpenerPolicy = "same-origin";
        /** Sent only on HTTPS requests (directly, or via X-Forwarded-Proto when trust-forwarded-for is on). */
        private long hstsMaxAgeSeconds = 31_536_000;
        /** CSP for the protected app's responses. Empty = none, because a wrong CSP breaks pages. */
        private String contentSecurityPolicy = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getFrameOptions() { return frameOptions; }
        public void setFrameOptions(String frameOptions) { this.frameOptions = frameOptions; }
        public String getReferrerPolicy() { return referrerPolicy; }
        public void setReferrerPolicy(String referrerPolicy) { this.referrerPolicy = referrerPolicy; }
        public String getPermissionsPolicy() { return permissionsPolicy; }
        public void setPermissionsPolicy(String permissionsPolicy) { this.permissionsPolicy = permissionsPolicy; }
        public String getCrossOriginOpenerPolicy() { return crossOriginOpenerPolicy; }
        public void setCrossOriginOpenerPolicy(String v) { this.crossOriginOpenerPolicy = v; }
        public long getHstsMaxAgeSeconds() { return hstsMaxAgeSeconds; }
        public void setHstsMaxAgeSeconds(long hstsMaxAgeSeconds) { this.hstsMaxAgeSeconds = hstsMaxAgeSeconds; }
        public String getContentSecurityPolicy() { return contentSecurityPolicy; }
        public void setContentSecurityPolicy(String v) { this.contentSecurityPolicy = v; }
    }

    public static class Detection {
        /** Paths where some or all attack detectors are skipped. */
        private List<Exclusion> exclusions = new ArrayList<>();

        public List<Exclusion> getExclusions() { return exclusions; }
        public void setExclusions(List<Exclusion> exclusions) { this.exclusions = exclusions; }
    }

    /**
     * Skips detectors on matching paths. The body-size limit, rate limiting and
     * IP blocking still apply.
     * <pre>
     * securegate.detection.exclusions[0].paths=/api/editor/**
     * securegate.detection.exclusions[0].types=XSS        # omit to skip SQLI, XSS and PATH_TRAVERSAL
     * </pre>
     */
    public static class Exclusion {
        private List<String> paths = new ArrayList<>();
        private List<AttackType> types = new ArrayList<>();

        public List<String> getPaths() { return paths; }
        public void setPaths(List<String> paths) { this.paths = paths; }
        public List<AttackType> getTypes() { return types; }
        public void setTypes(List<AttackType> types) { this.types = types; }
    }

    /**
     * Gateway mode. When {@code target-url} is set, SecureGate forwards every request
     * that passes its checks to that upstream app, except its own /admin API and
     * /dashboard. The protected app can then be written in any language.
     */
    public static class Proxy {
        /** Upstream base URL, e.g. http://my-app:8081. Empty = gateway mode off. */
        private String targetUrl = "";
        private long connectTimeoutMs = 5_000;
        private long readTimeoutMs = 30_000;
        /** Rewrite upstream redirects (Location headers) that point at target-url to relative paths. */
        private boolean rewriteRedirects = true;

        public String getTargetUrl() { return targetUrl; }
        public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
        public long getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(long v) { this.connectTimeoutMs = v; }
        public long getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(long v) { this.readTimeoutMs = v; }
        public boolean isRewriteRedirects() { return rewriteRedirects; }
        public void setRewriteRedirects(boolean v) { this.rewriteRedirects = v; }
        public boolean isEnabled() { return targetUrl != null && !targetUrl.isBlank(); }
    }

    public static class Admin {
        /** Shared secret expected in the X-Admin-Token header for /admin/**. */
        private String token = "change-me";
        /** Path prefix protected by the admin token. */
        private String pathPrefix = "/admin";

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
        public String getPathPrefix() { return pathPrefix; }
        public void setPathPrefix(String pathPrefix) { this.pathPrefix = pathPrefix; }
    }

    public static class RateLimit {
        private int maxRequests = 100;
        private long windowSeconds = 60;

        public int getMaxRequests() { return maxRequests; }
        public void setMaxRequests(int maxRequests) { this.maxRequests = maxRequests; }
        public long getWindowSeconds() { return windowSeconds; }
        public void setWindowSeconds(long windowSeconds) { this.windowSeconds = windowSeconds; }
    }

    public static class Blocking {
        private int maxViolations = 5;
        private long violationWindowSeconds = 600;
        /** How long an automatic block lasts; 0 means until manually removed. */
        private long blockDurationSeconds = 3600;
        /** IPs that are never rate limited or blocked. */
        private List<String> whitelist = new ArrayList<>();

        public int getMaxViolations() { return maxViolations; }
        public void setMaxViolations(int maxViolations) { this.maxViolations = maxViolations; }
        public long getViolationWindowSeconds() { return violationWindowSeconds; }
        public void setViolationWindowSeconds(long s) { this.violationWindowSeconds = s; }
        public long getBlockDurationSeconds() { return blockDurationSeconds; }
        public void setBlockDurationSeconds(long s) { this.blockDurationSeconds = s; }
        public List<String> getWhitelist() { return whitelist; }
        public void setWhitelist(List<String> whitelist) { this.whitelist = whitelist; }
    }

    public static class Alerts {
        private String logFile = "logs/alerts.json";
        private int maxPayloadLength = 500;

        public String getLogFile() { return logFile; }
        public void setLogFile(String logFile) { this.logFile = logFile; }
        public int getMaxPayloadLength() { return maxPayloadLength; }
        public void setMaxPayloadLength(int maxPayloadLength) { this.maxPayloadLength = maxPayloadLength; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public long getMaxBodySize() { return maxBodySize; }
    public void setMaxBodySize(long maxBodySize) { this.maxBodySize = maxBodySize; }
    public boolean isTrustForwardedFor() { return trustForwardedFor; }
    public void setTrustForwardedFor(boolean trustForwardedFor) { this.trustForwardedFor = trustForwardedFor; }
    public EnforcementMode getMode() { return mode; }
    public void setMode(EnforcementMode mode) { this.mode = mode; }
    public Headers getHeaders() { return headers; }
    public List<String> getExcludedPaths() { return excludedPaths; }
    public void setExcludedPaths(List<String> excludedPaths) { this.excludedPaths = excludedPaths; }
    public Detection getDetection() { return detection; }
    public Proxy getProxy() { return proxy; }
    public Admin getAdmin() { return admin; }
    public RateLimit getRateLimit() { return rateLimit; }
    public Blocking getBlocking() { return blocking; }
    public Alerts getAlerts() { return alerts; }
}
