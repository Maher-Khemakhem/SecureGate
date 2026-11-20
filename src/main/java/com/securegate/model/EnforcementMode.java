package com.securegate.model;

/**
 * Whether SecureGate blocks what it detects.
 */
public enum EnforcementMode {
    /** Attacks, rate-limit hits and oversized bodies are rejected (400 / 429). */
    ENFORCE,
    /**
     * Everything is detected and logged with {@code "action":"DETECTED"}, but requests are let through
     * and no automatic IP blocks are created. Use it to tune false positives on real traffic first.
     * IPs an admin blocked explicitly stay blocked.
     */
    MONITOR
}
