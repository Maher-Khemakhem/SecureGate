package com.securegate.filter;

import com.securegate.config.SecurityProperties;
import com.securegate.model.AttackType;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves which SecureGate checks are switched off for a request path.
 * Patterns are Ant-style ({@code /api/editor/**}, {@code /files/*.txt}) and are
 * matched against the canonical path, so encoding tricks cannot be used to
 * make a request look like it targets an excluded path.
 */
public class PathExclusions {

    private static final Logger log = LoggerFactory.getLogger(PathExclusions.class);

    /** Detectors that can be excluded. The body-size limit is always enforced. */
    public static final Set<AttackType> DETECTABLE =
            Collections.unmodifiableSet(EnumSet.of(AttackType.SQLI, AttackType.XSS, AttackType.PATH_TRAVERSAL,
                    AttackType.COMMAND_INJECTION, AttackType.SSRF, AttackType.LOG4SHELL, AttackType.NOSQLI));

    private record Rule(String pattern, Set<AttackType> types) {
    }

    private final AntPathMatcher matcher = new AntPathMatcher();
    private final List<String> bypass;
    private final List<Rule> detectionRules = new ArrayList<>();

    public PathExclusions(SecurityProperties properties) {
        this.bypass = List.copyOf(properties.getExcludedPaths());
        bypass.forEach(PathExclusions::validatePattern);

        List<SecurityProperties.Exclusion> exclusions = properties.getDetection().getExclusions();
        for (int i = 0; i < exclusions.size(); i++) {
            SecurityProperties.Exclusion exclusion = exclusions.get(i);
            if (exclusion.getPaths().isEmpty()) {
                throw new IllegalStateException("securegate.detection.exclusions[" + i + "].paths must not be empty");
            }
            Set<AttackType> types = exclusion.getTypes().isEmpty()
                    ? DETECTABLE
                    : EnumSet.copyOf(exclusion.getTypes());
            if (!DETECTABLE.containsAll(types)) {
                throw new IllegalStateException("securegate.detection.exclusions[" + i + "].types may only contain "
                        + DETECTABLE + " (the body-size limit cannot be excluded), got " + exclusion.getTypes());
            }
            for (String pattern : exclusion.getPaths()) {
                validatePattern(pattern);
                detectionRules.add(new Rule(pattern, Collections.unmodifiableSet(types)));
            }
        }

        if (!bypass.isEmpty()) {
            log.warn("SecureGate is bypassed entirely for: {}", bypass);
        }
        detectionRules.forEach(r -> log.info("SecureGate skips {} detection for {}", r.types(), r.pattern()));
    }

    /** True if the request skips IP blocking, rate limiting and attack detection. */
    public boolean isBypassed(HttpServletRequest request) {
        if (bypass.isEmpty()) {
            return false;
        }
        String path = RequestPaths.canonical(request);
        for (String pattern : bypass) {
            if (matcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /** Detectors to skip for this request; empty when every detector applies. */
    public Set<AttackType> skippedDetectors(HttpServletRequest request) {
        if (detectionRules.isEmpty()) {
            return Set.of();
        }
        String path = RequestPaths.canonical(request);
        Set<AttackType> skipped = EnumSet.noneOf(AttackType.class);
        for (Rule rule : detectionRules) {
            if (matcher.match(rule.pattern(), path)) {
                skipped.addAll(rule.types());
            }
        }
        return skipped;
    }

    public List<String> bypassPatterns() {
        return bypass;
    }

    public List<String> describeDetectionRules() {
        return detectionRules.stream().map(r -> r.pattern() + " -> skip " + r.types()).toList();
    }

    private static void validatePattern(String pattern) {
        if (pattern == null || !pattern.startsWith("/")) {
            throw new IllegalStateException("SecureGate path patterns must start with '/', got: " + pattern);
        }
    }
}
