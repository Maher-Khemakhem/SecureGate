package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * Signature-based SQL injection detection (OWASP A03:2021 Injection).
 */
public class SqlInjectionDetector extends RegexAttackDetector {

    /** Whitespace or an inline SQL comment, which attackers use as a space substitute. */
    private static final String SP = "(?:\\s|/\\*.*?\\*/)+";

    private static final List<Rule> RULES = List.of(
            // Tautologies after breaking out of a string: ' OR 1=1, " or 'a'='a, ' AND 1=1
            // The operand may be wrapped in quotes and parentheses: ' OR ('1'='1
            rule("['\"`)]" + "\\s*(?:or|and|xor|\\|\\||&&)" + SP
                    + "[\\s'\"`(]*\\w*['\"`)]*\\s*(?:=|<|>|<>|!=|like\\b|is\\s+(?:not\\s+)?null\\b)",
                    "'", "\"", "`", ")"),
            // Numeric tautologies without a quote: 1 OR 1=1
            rule("\\b(?:or|and)" + SP + "(\\d+)\\s*=\\s*\\1\\b", "="),
            // UNION-based extraction: UNION SELECT, UNION ALL SELECT, UNION/**/SELECT
            rule("\\bunion" + SP + "(?:all" + SP + "|distinct" + SP + ")?select\\b", "union"),
            // Comment truncation after closing a string: admin'--, admin'#, '/*
            rule("['\"`]\\s*\\)*\\s*;?\\s*(?:--|#\\s*$|/\\*)", "--", "#", "/*"),
            // Stacked queries: ; DROP TABLE ...
            rule(";\\s*(?:drop|delete|insert|update|alter|create|truncate|exec|execute|shutdown|declare)\\b", ";"),
            // Time-based blind
            rule("\\b(?:sleep|benchmark|pg_sleep)\\s*\\(", "sleep", "benchmark"),
            rule("\\bwaitfor" + SP + "delay\\b", "waitfor"),
            // Fingerprinting and dangerous built-ins
            rule("\\binformation_schema\\b", "information_schema"),
            rule("@@version\\b", "@@version"),
            rule("\\bxp_cmdshell\\b", "xp_cmdshell"),
            rule("\\bload_file\\s*\\(", "load_file"),
            rule("\\binto" + SP + "(?:out|dump)file\\b", "outfile", "dumpfile"),
            // Classic tautology string as a whole value
            rule("^\\s*['\"]\\s*or\\s*['\"]", "or")
    );

    public SqlInjectionDetector() {
        super(RULES);
    }

    @Override
    public AttackType type() {
        return AttackType.SQLI;
    }
}
