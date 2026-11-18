package com.securegate.filter.detector;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Base class for detectors that match a list of regular expressions against
 * the normalised input.
 */
public abstract class RegexAttackDetector implements AttackDetector {

    private final List<Pattern> patterns;

    protected RegexAttackDetector(List<String> regexes) {
        this.patterns = regexes.stream()
                .map(r -> Pattern.compile(r, Pattern.CASE_INSENSITIVE | Pattern.DOTALL))
                .toList();
    }

    @Override
    public boolean detect(String input) {
        if (input == null || input.isBlank()) {
            return false;
        }
        String normalized = InputNormalizer.normalize(input);
        return matchesAny(normalized) || matchesRaw(input);
    }

    protected boolean matchesAny(String value) {
        for (Pattern p : patterns) {
            if (p.matcher(value).find()) {
                return true;
            }
        }
        return false;
    }

    /** Hook for detectors that also need to inspect the un-decoded input. */
    protected boolean matchesRaw(String raw) {
        return false;
    }
}
