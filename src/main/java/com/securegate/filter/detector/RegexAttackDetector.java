package com.securegate.filter.detector;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Base class for detectors that match a list of regular expressions against
 * the normalised input.
 * <p>
 * Each {@link Rule} can name literals that every match must contain. The regex only runs if the
 * input contains at least one of them: an {@code indexOf} costs a fraction of a regex scan, and
 * ordinary text rarely contains the trigger, so most rules never run for normal traffic.
 */
public abstract class RegexAttackDetector implements AttackDetector {

    /**
     * A pattern plus the literals that gate it.
     *
     * @param requiresAny lower-case literals; the pattern runs only if the normalised input contains at
     *                    least one. Empty means "always run". A literal that a match does not necessarily
     *                    contain would create false negatives, so keep these conservative.
     */
    protected record Rule(String regex, List<String> requiresAny) {
    }

    /** A rule gated on at least one of the given literals being present. */
    protected static Rule rule(String regex, String... requiresAny) {
        return new Rule(regex, List.of(requiresAny));
    }

    private record Compiled(Pattern pattern, String[] requiresAny) {
        boolean worthRunning(String normalized) {
            if (requiresAny.length == 0) {
                return true;
            }
            for (String literal : requiresAny) {
                if (normalized.contains(literal)) {
                    return true;
                }
            }
            return false;
        }
    }

    private final List<Compiled> rules;

    /**
     * Patterns run against {@link InputNormalizer#normalize} output, which is already lower-case,
     * so they are compiled case-sensitive: case-insensitive matching is markedly slower, and
     * every request pays for it. Write patterns and {@code requiresAny} literals in lower case.
     */
    protected RegexAttackDetector(List<Rule> rules) {
        this.rules = rules.stream()
                .map(r -> new Compiled(Pattern.compile(r.regex(), Pattern.DOTALL), r.requiresAny().toArray(String[]::new)))
                .toList();
    }

    @Override
    public boolean detect(String input) {
        if (input == null || input.isBlank()) {
            return false;
        }
        return detect(input, InputNormalizer.normalize(input));
    }

    /** Lets the filter normalise each input once and share the result between all detectors. */
    @Override
    public boolean detect(String raw, String normalized) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        return matchesAny(normalized) || matchesRaw(raw);
    }

    protected boolean matchesAny(String value) {
        for (Compiled rule : rules) {
            if (rule.worthRunning(value) && rule.pattern().matcher(value).find()) {
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
