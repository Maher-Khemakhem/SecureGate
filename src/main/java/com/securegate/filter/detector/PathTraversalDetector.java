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

    private static final List<Rule> RULES = List.of(
            // ../  ..\  and trailing /..
            rule("\\.\\.[/\\\\]", ".."),
            rule("[/\\\\]\\.\\.(?:[/\\\\]|$)", ".."),
            rule("^\\.\\.$", ".."),
            // Well-known sensitive targets
            rule("(?:^|[/\\\\])etc[/\\\\](?:passwd|shadow|hosts|group)\\b", "etc"),
            rule("(?:^|[/\\\\])proc[/\\\\]self[/\\\\]", "proc"),
            rule("[a-z]:[/\\\\]+(?:windows|winnt|boot\\.ini)", "windows", "winnt", "boot.ini"),
            rule("\\bwin\\.ini\\b", "win.ini"),
            // Wrapper schemes used for LFI
            rule("\\b(?:file|php|zip|phar|expect)://", "://")
    );

    /**
     * Encodings that do not survive normal UTF-8 decoding (overlong UTF-8,
     * IIS %u encoding), so they are checked on the raw input.
     */
    private static final Pattern RAW_ENCODED = Pattern.compile(
            // (?:25)* also matches the double and triple encoded forms (%25c0%25af, %2500)
            "%(?:25)*c0%(?:25)*a[ef]|%(?:25)*c1%(?:25)*9c|%(?:25)*c0%(?:25)*2[fe]|%(?:25)*e0%(?:25)*80%(?:25)*af"
                    + "|%u002e|%u2215|%u2216|%uff0e|%(?:25)+2e|%(?:25)*00",
            Pattern.CASE_INSENSITIVE);

    public PathTraversalDetector() {
        super(RULES);
    }

    @Override
    protected boolean matchesRaw(String raw) {
        // Every alternative starts with '%', and almost no input contains one.
        if (raw.indexOf('%') < 0) {
            return false;
        }
        return RAW_ENCODED.matcher(raw.toLowerCase(Locale.ROOT)).find();
    }

    @Override
    public AttackType type() {
        return AttackType.PATH_TRAVERSAL;
    }
}
