package com.securegate.service;

import com.securegate.config.SecurityProperties;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory sliding-window-log rate limiter keyed by client IP.
 * <p>
 * Each IP keeps the timestamps of its accepted requests inside the current
 * window. A request is allowed only if fewer than {@code maxRequests}
 * timestamps fall within the last {@code windowSeconds}, which avoids the
 * burst-at-boundary problem of fixed windows.
 */
public class RateLimiterService {

    private final SecurityProperties.RateLimit config;
    private final Clock clock;
    private final Map<String, Deque<Long>> windows = new ConcurrentHashMap<>();

    public RateLimiterService(SecurityProperties properties, Clock clock) {
        this.config = properties.getRateLimit();
        this.clock = clock;
    }

    /**
     * Records a request for {@code ip} and returns whether it is within the limit.
     * Rejected requests are not counted, so a client that backs off recovers
     * as soon as old requests slide out of the window.
     */
    public boolean tryAcquire(String ip) {
        long now = clock.millis();
        long windowStart = now - windowMillis();
        Deque<Long> timestamps = windows.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            evictOlderThan(timestamps, windowStart);
            if (timestamps.size() >= config.getMaxRequests()) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    /** Seconds until the oldest request in the window expires (for Retry-After). */
    public long retryAfterSeconds(String ip) {
        Deque<Long> timestamps = windows.get(ip);
        if (timestamps == null) {
            return 0;
        }
        synchronized (timestamps) {
            Long oldest = timestamps.peekFirst();
            if (oldest == null) {
                return 0;
            }
            long millis = oldest + windowMillis() - clock.millis();
            return Math.max(1, (millis + 999) / 1000);
        }
    }

    public int currentCount(String ip) {
        Deque<Long> timestamps = windows.get(ip);
        if (timestamps == null) {
            return 0;
        }
        synchronized (timestamps) {
            evictOlderThan(timestamps, clock.millis() - windowMillis());
            return timestamps.size();
        }
    }

    public void reset(String ip) {
        windows.remove(ip);
    }

    /** Drops idle IPs so memory stays bounded by the number of active clients. */
    @Scheduled(fixedDelayString = "${securegate.rate-limit.cleanup-interval-ms:60000}")
    public void cleanup() {
        long windowStart = clock.millis() - windowMillis();
        windows.entrySet().removeIf(entry -> {
            Deque<Long> timestamps = entry.getValue();
            synchronized (timestamps) {
                evictOlderThan(timestamps, windowStart);
                return timestamps.isEmpty();
            }
        });
    }

    private long windowMillis() {
        return config.getWindowSeconds() * 1000L;
    }

    private static void evictOlderThan(Deque<Long> timestamps, long windowStart) {
        while (!timestamps.isEmpty() && timestamps.peekFirst() <= windowStart) {
            timestamps.pollFirst();
        }
    }
}
