package com.securegate.service;

import com.securegate.config.SecurityProperties;
import com.securegate.model.EnforcementMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the current enforcement mode. Starts from {@code securegate.mode} and can be
 * switched at runtime (admin API / dashboard) without a restart. The change lasts
 * until the next restart; set {@code securegate.mode} to make it permanent.
 */
public class ModeService {

    private static final Logger log = LoggerFactory.getLogger(ModeService.class);

    private final AtomicReference<EnforcementMode> mode;

    public ModeService(SecurityProperties properties) {
        this.mode = new AtomicReference<>(properties.getMode());
        if (properties.getMode() == EnforcementMode.MONITOR) {
            log.warn("SecureGate started in MONITOR mode: attacks are logged but NOT blocked");
        }
    }

    public EnforcementMode get() {
        return mode.get();
    }

    public boolean isMonitor() {
        return mode.get() == EnforcementMode.MONITOR;
    }

    public void set(EnforcementMode newMode) {
        EnforcementMode old = mode.getAndSet(newMode);
        if (old != newMode) {
            log.warn("SecureGate enforcement mode changed: {} -> {}", old, newMode);
        }
    }
}
