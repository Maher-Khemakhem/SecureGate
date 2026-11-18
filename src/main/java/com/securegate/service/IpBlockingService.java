package com.securegate.service;

import com.securegate.config.SecurityProperties;
import com.securegate.model.BlockedIp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks security violations per IP and automatically blocks an IP once it
 * reaches {@code maxViolations} within {@code violationWindowSeconds}.
 */
public class IpBlockingService {

    private static final Logger log = LoggerFactory.getLogger(IpBlockingService.class);

    private final SecurityProperties.Blocking config;
    private final Clock clock;
    private final Set<String> whitelist;
    private final Map<String, Deque<Long>> violations = new ConcurrentHashMap<>();
    private final Map<String, BlockedIp> blocked = new ConcurrentHashMap<>();

    public IpBlockingService(SecurityProperties properties, Clock clock) {
        this.config = properties.getBlocking();
        this.clock = clock;
        this.whitelist = Set.copyOf(config.getWhitelist());
    }

    public boolean isWhitelisted(String ip) {
        return whitelist.contains(ip);
    }

    public boolean isBlocked(String ip) {
        return getActiveBlock(ip).isPresent();
    }

    public Optional<BlockedIp> getActiveBlock(String ip) {
        BlockedIp entry = blocked.get(ip);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.isExpired(clock.instant())) {
            blocked.remove(ip, entry);
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    /**
     * Records one violation and blocks the IP if the threshold is reached.
     *
     * @return true if this violation caused the IP to become blocked
     */
    public boolean recordViolation(String ip, String reason) {
        if (isWhitelisted(ip) || isBlocked(ip)) {
            return false;
        }
        long now = clock.millis();
        long windowStart = now - config.getViolationWindowSeconds() * 1000L;
        Deque<Long> history = violations.computeIfAbsent(ip, k -> new ArrayDeque<>());
        int count;
        synchronized (history) {
            while (!history.isEmpty() && history.peekFirst() <= windowStart) {
                history.pollFirst();
            }
            history.addLast(now);
            count = history.size();
            if (count < config.getMaxViolations()) {
                return false;
            }
            history.clear();
        }
        block(ip, "Automatic block: " + count + " violations within "
                + config.getViolationWindowSeconds() + "s (last: " + reason + ")", count);
        return true;
    }

    public BlockedIp block(String ip, String reason, int violationCount) {
        Instant now = clock.instant();
        Instant expiresAt = config.getBlockDurationSeconds() > 0
                ? now.plusSeconds(config.getBlockDurationSeconds())
                : null;
        BlockedIp entry = new BlockedIp(ip, now, expiresAt, reason, violationCount);
        blocked.put(ip, entry);
        log.warn("SecureGate blocked IP {} until {}: {}", ip, expiresAt == null ? "manual unblock" : expiresAt, reason);
        return entry;
    }

    /** @return true if the IP was blocked and is now released */
    public boolean unblock(String ip) {
        violations.remove(ip);
        BlockedIp removed = blocked.remove(ip);
        if (removed != null) {
            log.info("SecureGate unblocked IP {}", ip);
        }
        return removed != null && !removed.isExpired(clock.instant());
    }

    public List<BlockedIp> listBlocked() {
        Instant now = clock.instant();
        blocked.values().removeIf(b -> b.isExpired(now));
        return blocked.values().stream()
                .sorted(Comparator.comparing(BlockedIp::blockedAt).reversed())
                .toList();
    }

    public int violationCount(String ip) {
        Deque<Long> history = violations.get(ip);
        if (history == null) {
            return 0;
        }
        long windowStart = clock.millis() - config.getViolationWindowSeconds() * 1000L;
        synchronized (history) {
            return (int) history.stream().filter(t -> t > windowStart).count();
        }
    }

    @Scheduled(fixedDelayString = "${securegate.blocking.cleanup-interval-ms:60000}")
    public void cleanup() {
        Instant now = clock.instant();
        blocked.values().removeIf(b -> b.isExpired(now));
        long windowStart = clock.millis() - config.getViolationWindowSeconds() * 1000L;
        violations.entrySet().removeIf(entry -> {
            Deque<Long> history = entry.getValue();
            synchronized (history) {
                while (!history.isEmpty() && history.peekFirst() <= windowStart) {
                    history.pollFirst();
                }
                return history.isEmpty();
            }
        });
    }
}
