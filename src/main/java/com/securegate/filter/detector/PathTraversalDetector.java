package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Path traversal / local file inclusion detection
 * (OWASP A01:2021 Broken Access Control, CWE-22).
 */
public class PathTraversalDetector extends RegexAttackDetector {

    private static final List<String> PATTERNS = List.of(
            // ../  ..\  and trailing /..
            "\\.\\.[/\\\\]",
            "[/\\\\]\\.\\.(?:[/\\\\]|$)",
            "^\\.\\.$",
            // Well-known sensitive targets
            "(?:^|[/\\\\])etc[/\\\\](?:passwd|shadow|hosts|group)\\b",
            "(?:^|[/\\\\])proc[/\\\\]self[/\\\\]",
            "[a-z]:[/\\\\]+(?:windows|winnt|boot\\.ini)",
            "\\bwin\\.ini\\b",
            // Wrapper schemes used for LFI
            "\\b(?:file|php|zip|phar|expect)://"
    );

    /**
     * Encodings that do not survive normal UTF-8 decoding (overlong UTF-8,
     * IIS %u encoding), so they are checked on the raw input.
     */
    private static final Pattern RAW_ENCODED = Pattern.compile(
            "%c0%a[ef]|%c1%9c|%c0%2f|%e0%80%af|%u002e|%u2215|%u2216|%uff0e|%252e|\\.\\.%00|%00",
            Pattern.CASE_INSENSITIVE);

    public PathTraversalDetector() {
        super(PATTERNS);
    }

    @Override
    protected boolean matchesRaw(String raw) {
        return RAW_ENCODED.matcher(raw.toLowerCase(Locale.ROOT)).find();
    }

    @Override
    public AttackType type() {
        return AttackType.PATH_TRAVERSAL;
    }
}
