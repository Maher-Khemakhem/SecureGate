package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * NoSQL (MongoDB-style) operator injection detection (OWASP A03:2021 Injection, CWE-943).
 * <p>
 * Catches operator injection in all three shapes attackers use:
 * a JSON key such as {@code "$ne"}, a bracketed parameter such as {@code user[$ne]=x},
 * and an operator object inside a string such as {@code {"$gt":""}}.
 */
public class NoSqlInjectionDetector extends RegexAttackDetector {

    private static final String OPS = "(?:gte?|lte?|ne|eq|nin|in|regex|where|exists|expr|or|and|nor|not|function"
            + "|accumulator|elemmatch|size|all|type|mod|text|jsonschema|options)";

    private static final List<Rule> RULES = List.of(
            // A whole value that is just an operator: JSON key "$ne" is inspected on its own
            rule("^\\s*\\$" + OPS + "\\s*$", "$"),
            // user[$ne]=x   password[$regex]=.*
            rule("\\[\\s*\\$" + OPS + "\\s*]", "$"),
            // {"$gt": ""}   {'$ne': null}
            rule("\\{\\s*[\"']?\\$" + OPS + "[\"']?\\s*:", "$"),
            // JavaScript injection into $where / mapReduce
            rule("\\$where\\s*[:=]", "$where"),
            rule("['\"]\\s*(?:\\|\\||&&)\\s*['\"]?\\w*['\"]?\\s*[=!]=", "||", "&&"),
            // '; return true; var x='   (closing a $where string and appending JavaScript)
            rule("['\"]\\s*;\\s*return\\s+(?:true|false|1|!?0)\\b", "return"),
            rule("\\bdb\\.\\w+\\.(?:find|insert|update|remove|drop|aggregate)\\w*\\s*\\(", "db.")
    );

    public NoSqlInjectionDetector() {
        super(RULES);
    }

    @Override
    public AttackType type() {
        return AttackType.NOSQLI;
    }
}
