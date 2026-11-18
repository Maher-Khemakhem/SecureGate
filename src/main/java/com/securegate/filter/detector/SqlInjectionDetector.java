package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * Signature-based SQL injection detection (OWASP A03:2021 Injection).
 */
public class SqlInjectionDetector extends RegexAttackDetector {

    /** Whitespace or an inline SQL comment, which attackers use as a space substitute. */
    private static final String SP = "(?:\\s|/\\*.*?\\*/)+";

    private static final List<String> PATTERNS = List.of(
            // Tautologies after breaking out of a string: ' OR 1=1, " or 'a'='a, ' AND 1=1
            "['\"`)]" + "\\s*(?:or|and|xor|\\|\\||&&)" + SP + "['\"`(]?\\w*['\"`]?\\s*(?:=|<|>|<>|!=|like\\b|is\\b)",
            // Numeric tautologies without a quote: 1 OR 1=1
            "\\b(?:or|and)" + SP + "(\\d+)\\s*=\\s*\\1\\b",
            // UNION-based extraction: UNION SELECT, UNION ALL SELECT, UNION/**/SELECT
            "\\bunion" + SP + "(?:all" + SP + "|distinct" + SP + ")?select\\b",
            // Comment truncation after closing a string: admin'--, admin'#, '/*
            "['\"`]\\s*\\)*\\s*;?\\s*(?:--|#\\s*$|/\\*)",
            // Stacked queries: ; DROP TABLE ...
            ";\\s*(?:drop|delete|insert|update|alter|create|truncate|exec|execute|shutdown|declare)\\b",
            // Time-based blind
            "\\b(?:sleep|benchmark|pg_sleep)\\s*\\(",
            "\\bwaitfor" + SP + "delay\\b",
            // Fingerprinting and dangerous built-ins
            "\\binformation_schema\\b",
            "@@version\\b",
            "\\bxp_cmdshell\\b",
            "\\bload_file\\s*\\(",
            "\\binto" + SP + "(?:out|dump)file\\b",
            // Classic tautology string as a whole value
            "^\\s*['\"]\\s*or\\s*['\"]"
    );

    public SqlInjectionDetector() {
        super(PATTERNS);
    }

    @Override
    public AttackType type() {
        return AttackType.SQLI;
    }
}
