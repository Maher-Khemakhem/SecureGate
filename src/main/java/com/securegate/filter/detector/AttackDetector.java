package com.securegate.filter.detector;

import com.securegate.model.AttackType;

/**
 * A stateless detector for one class of attack. Implementations receive the raw,
 * untrusted value and are responsible for normalising it.
 */
public interface AttackDetector {

    AttackType type();

    boolean detect(String input);
}
