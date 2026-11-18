package com.securegate.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * One line of logs/alerts.json.
 */
@JsonPropertyOrder({"timestamp", "ip", "attack_type", "endpoint", "payload", "action"})
public record AlertEntry(
        @JsonProperty("timestamp") String timestamp,
        @JsonProperty("ip") String ip,
        @JsonProperty("attack_type") String attackType,
        @JsonProperty("endpoint") String endpoint,
        @JsonProperty("payload") String payload,
        @JsonProperty("action") String action
) {
}
