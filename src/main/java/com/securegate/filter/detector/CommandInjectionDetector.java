package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * OS command injection detection (OWASP A03:2021 Injection, CWE-78).
 * <p>
 * A shell metacharacter alone ({@code ;}, {@code |}, {@code &&}) is ordinary text, so every
 * pattern needs a shell metacharacter <em>and</em> a command that is unlikely in prose, or
 * a command with argument syntax ({@code cat /etc/passwd}, {@code rm -rf}). A single
 * {@code &} is deliberately not a separator: it joins query parameters, and parameters
 * named {@code uname} or {@code id} are common.
 */
public class CommandInjectionDetector extends RegexAttackDetector {

    /** Shell command separators. */
    private static final String SEP = "(?:;|\\|{1,2}|&&)\\s*";

    /** Commands that are almost never ordinary words. */
    private static final String STRONG = "(?:whoami|uname|ifconfig|ipconfig|nslookup|netstat|systeminfo|tasklist"
            + "|powershell|pwsh|wget|netcat|ncat|chmod|chown|crontab|telnet|useradd|bash|zsh|ksh"
            + "|/bin/\\w+|/usr/bin/\\w+|net\\s+user)\\b";

    /** Commands ambiguous in prose, accepted with shell-style arguments. */
    private static final String SHELL_CMDS = "(?:whoami|uname|cat\\s+[/~.\\\\]|curl\\s|wget\\s|nc\\s|sleep\\s+\\d|ping\\s+-|bash\\b|sh\\s+-c)";

    /** Literals gating every SEP-based rule: without one of these there is no shell separator. */
    private static final String[] SEPARATORS = {";", "|", "&&"};

    private static final List<Rule> RULES = List.of(
            // ; whoami   | uname -a   && /bin/sh
            rule(SEP + STRONG, SEPARATORS),
            // ; cat /etc/passwd   | head -n 5 ~/x
            rule(SEP + "(?:cat|head|tail|more|less|tac|nl)\\s+(?:-\\w+\\s+)*[/~.\\\\$]", SEPARATORS),
            // ; ls   ; ls -la   ; ls /
            rule(SEP + "(?:ls|dir)(?:\\s+-[a-z]+)*\\s*(?:$|[;|&<>)`]|[/\\\\~])", SEPARATORS),
            // ; id   ; pwd   ; env (only when the command ends the statement)
            rule(SEP + "(?:id|pwd|env|printenv|hostname|ps)\\s*(?:$|[;|&)`<>])", SEPARATORS),
            // ; rm -rf /   ; sleep 10   ; ping -c 4 host   ; curl http://...
            rule(SEP + "rm\\s+-", SEPARATORS),
            rule(SEP + "sleep\\s+\\d", SEPARATORS),
            rule(SEP + "ping\\s+(?:-[a-z]\\s*\\d*\\s+)*(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[a-z0-9-]+\\.[a-z]{2,})", SEPARATORS),
            rule(SEP + "curl\\s+(?:-\\w+\\s+)*(?:https?://|-)", SEPARATORS),
            // Command substitution $(cmd) and `cmd`
            rule("\\$\\(\\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|sleep|ping|echo|bash|sh|pwd|env|hostname)\\b", "$("),
            rule("`\\s*" + SHELL_CMDS, "`"),
            // ${IFS} whitespace trick: cat${IFS}/etc/passwd
            rule("\\$\\{?ifs\\}?", "ifs"),
            // Interpreters and reverse shells
            rule("\\b(?:sh|bash)\\s+-[ci]\\b", "sh"),
            rule("\\bpython\\d*\\s+-c\\b", "python"),
            rule("\\bperl\\s+-e\\b", "perl"),
            rule("\\bnc\\s+(?:-\\w+\\s+)+", "nc"),
            rule("/dev/tcp/", "/dev/tcp/"),
            rule("\\bmkfifo\\b", "mkfifo"),
            rule("\\|\\s*(?:sh|bash)\\s*$", "|"),
            rule("\\brm\\s+-[rf]+\\s+/", "rm"),
            rule("\\s>\\s*/(?:tmp|dev/null|etc|var)/?", ">"),
            // Windows. A single '&' needs a following space: "&uname=bob" joins query parameters.
            rule("&\\s+(?:whoami|ipconfig|systeminfo|tasklist|netstat|nslookup|net\\s+user)\\b", "&"),
            rule("\\bcmd(?:\\.exe)?\\s+/[ck]\\b", "cmd"),
            rule("\\bpowershell(?:\\.exe)?\\s+-(?:enc|e|c|command|nop|w)\\w*", "powershell"),
            rule("%comspec%", "%comspec%"),
            // Newline injection into a shell: value\nwhoami
            rule("[\\r\\n]\\s*(?:whoami|uname|wget\\s|nslookup|powershell|/bin/)", "\n", "\r")
    );

    public CommandInjectionDetector() {
        super(RULES);
    }

    @Override
    public AttackType type() {
        return AttackType.COMMAND_INJECTION;
    }
}
