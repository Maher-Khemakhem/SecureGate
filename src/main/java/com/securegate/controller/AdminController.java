package com.securegate.controller;

import com.securegate.config.SecurityProperties;
import com.securegate.filter.SecurityResponses;
import com.securegate.model.AlertEntry;
import com.securegate.model.BlockedIp;
import com.securegate.service.AlertLoggerService;
import com.securegate.service.IpBlockingService;
import com.securegate.service.ModeService;
import com.securegate.model.EnforcementMode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Monitoring and IP management API. Every call requires the
 * {@code X-Admin-Token} header (enforced by AdminAuthFilter).
 */
@RestController
@RequestMapping("/admin")
@ConditionalOnProperty(prefix = "securegate", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AdminController {

    private static final int DEFAULT_ALERT_LIMIT = 50;
    /** IPv4 or IPv6 literal (loose check; only used to reject obvious garbage). */
    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    private final IpBlockingService blockingService;
    private final AlertLoggerService alertLogger;
    private final SecurityProperties properties;
    private final ModeService modeService;

    public AdminController(IpBlockingService blockingService, AlertLoggerService alertLogger,
                           SecurityProperties properties, ModeService modeService) {
        this.blockingService = blockingService;
        this.alertLogger = alertLogger;
        this.properties = properties;
        this.modeService = modeService;
    }

    /** Current enforcement mode (ENFORCE blocks attacks, MONITOR only logs them). */
    @GetMapping("/mode")
    public Map<String, Object> mode() {
        return Map.of("enforcement", modeService.get());
    }

    /**
     * Switches the enforcement mode at runtime: {@code {"mode":"MONITOR"}} or {@code {"mode":"ENFORCE"}}.
     * The change lasts until restart; set {@code securegate.mode} to make it permanent.
     */
    @PutMapping("/mode")
    public ResponseEntity<Map<String, Object>> setMode(@RequestBody Map<String, String> request) {
        String value = request.getOrDefault("mode", "").trim().toUpperCase(java.util.Locale.ROOT);
        EnforcementMode newMode;
        try {
            newMode = EnforcementMode.valueOf(value);
        } catch (IllegalArgumentException e) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", "mode must be ENFORCE or MONITOR");
            return ResponseEntity.badRequest().body(error);
        }
        modeService.set(newMode);
        return ResponseEntity.ok(Map.of("enforcement", modeService.get()));
    }

    /** Active limits plus the caller's IP as SecureGate sees it (used by the dashboard). */
    @GetMapping("/config")
    public Map<String, Object> config(HttpServletRequest request) {
        Map<String, Object> rateLimit = new LinkedHashMap<>();
        rateLimit.put("max_requests", properties.getRateLimit().getMaxRequests());
        rateLimit.put("window_seconds", properties.getRateLimit().getWindowSeconds());

        Map<String, Object> blocking = new LinkedHashMap<>();
        blocking.put("max_violations", properties.getBlocking().getMaxViolations());
        blocking.put("violation_window_seconds", properties.getBlocking().getViolationWindowSeconds());
        blocking.put("block_duration_seconds", properties.getBlocking().getBlockDurationSeconds());
        blocking.put("whitelist", properties.getBlocking().getWhitelist());

        String ip = SecurityResponses.clientIp(request, properties);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("mode", properties.getProxy().isEnabled() ? "gateway" : "embedded");
        body.put("enforcement", modeService.get());
        body.put("upstream", properties.getProxy().isEnabled() ? properties.getProxy().getTargetUrl() : null);
        body.put("your_ip", ip);
        body.put("your_violations", blockingService.violationCount(ip));
        body.put("max_body_size", properties.getMaxBodySize());
        body.put("rate_limit", rateLimit);
        body.put("blocking", blocking);

        Map<String, Object> exclusions = new LinkedHashMap<>();
        exclusions.put("bypass_paths", properties.getExcludedPaths());
        exclusions.put("detection", properties.getDetection().getExclusions().stream()
                .map(e -> Map.of("paths", e.getPaths(),
                        "skips", e.getTypes().isEmpty()
                                ? com.securegate.filter.PathExclusions.DETECTABLE : e.getTypes()))
                .toList());
        body.put("exclusions", exclusions);
        return body;
    }

    /** Manually block an IP: {@code {"ip": "1.2.3.4", "reason": "optional"}}. */
    @PostMapping("/blocked-ips")
    public ResponseEntity<Map<String, Object>> block(@RequestBody Map<String, String> request) {
        String ip = request.getOrDefault("ip", "").trim();
        if (!IP_LITERAL.matcher(ip).matches()) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", "Invalid IP address");
            return ResponseEntity.badRequest().body(error);
        }
        String reason = request.get("reason");
        BlockedIp entry = blockingService.block(ip,
                reason == null || reason.isBlank() ? "Manual block by admin" : "Manual block: " + reason, 0);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("blocked", true);
        body.put("entry", entry);
        return ResponseEntity.status(201).body(body);
    }

    @GetMapping("/blocked-ips")
    public Map<String, Object> blockedIps() {
        List<BlockedIp> blocked = blockingService.listBlocked();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("count", blocked.size());
        body.put("blocked_ips", blocked);
        return body;
    }

    @DeleteMapping("/blocked-ips/{ip}")
    public ResponseEntity<Map<String, Object>> unblock(@PathVariable String ip) {
        boolean removed = blockingService.unblock(ip);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ip", ip);
        body.put("unblocked", removed);
        if (!removed) {
            body.put("message", "IP was not blocked");
            return ResponseEntity.status(404).body(body);
        }
        return ResponseEntity.ok(body);
    }

    /** Last 50 alerts (or {@code ?limit=n}, max 500), newest first. */
    @GetMapping("/alerts")
    public Map<String, Object> alerts(@RequestParam(defaultValue = "" + DEFAULT_ALERT_LIMIT) int limit) {
        int bounded = Math.max(1, Math.min(limit, 500));
        List<AlertEntry> alerts = alertLogger.recent(bounded);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("count", alerts.size());
        body.put("alerts", alerts);
        return body;
    }
}
