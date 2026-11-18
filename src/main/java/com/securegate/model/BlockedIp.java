package com.securegate.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * An IP currently denied by the middleware.
 *
 * @param expiresAt null when the block is permanent (until manually removed)
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record BlockedIp(
        @JsonProperty("ip") String ip,
        @JsonProperty("blocked_at") Instant blockedAt,
        @JsonProperty("expires_at") Instant expiresAt,
        @JsonProperty("reason") String reason,
        @JsonProperty("violation_count") int violationCount
) {
    public boolean isExpired(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }
}
