package com.securegate.filter.detector;

import com.securegate.model.AttackType;

/**
 * A stateless detector for one class of attack. Implementations receive the raw,
 * untrusted value and are responsible for normalising it.
 */
public interface AttackDetector {

    AttackType type();

    boolean detect(String input);

    /**
     * Same as {@link #detect(String)} but with the input already run through
     * {@link InputNormalizer#normalize}, so one normalisation is shared by every detector.
     * Detectors that do not use the normalised form can ignore it.
     */
    default boolean detect(String raw, String normalized) {
        return detect(raw);
    }

    /**
     * Whether this detector should also look at request headers and cookies.
     * Detectors whose signature is normal in browser-set headers (for example an
     * {@code Origin: http://localhost:5173} header for SSRF) return false.
     */
    default boolean appliesToHeaders() {
        return true;
    }
}
