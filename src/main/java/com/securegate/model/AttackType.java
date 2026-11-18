package com.securegate.model;

/**
 * Categories written to the {@code attack_type} field of alerts and used in block reasons.
 */
public enum AttackType {
    SQLI("SQLi", "SQLi detected"),
    XSS("XSS", "XSS detected"),
    PATH_TRAVERSAL("PATH_TRAVERSAL", "Path traversal detected"),
    OVERSIZED_PAYLOAD("OVERSIZED_PAYLOAD", "Payload too large"),
    RATE_LIMIT("RATE_LIMIT", "Rate limit exceeded"),
    BLOCKED_IP("BLOCKED_IP", "IP address is blocked");

    private final String label;
    private final String reason;

    AttackType(String label, String reason) {
        this.label = label;
        this.reason = reason;
    }

    /** Value used in alerts.json, e.g. "SQLi". */
    public String label() { return label; }

    /** Human-readable reason used in the blocked response body. */
    public String reason() { return reason; }
}
