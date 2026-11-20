package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * Server-side request forgery detection (OWASP A10:2021, CWE-918).
 * <p>
 * Flags URLs that point at internal infrastructure: loopback, private ranges, link-local
 * cloud metadata endpoints, numeric (decimal, hex, octal) IP encodings, {@code user@host}
 * tricks and non-HTTP schemes used to talk to internal services. A bare IP or
 * {@code localhost} without a URL scheme is plain text and is not flagged.
 * <p>
 * Request headers are not inspected: browsers legitimately send
 * {@code Origin: http://localhost:5173} and {@code Referer} headers during development.
 */
public class SsrfDetector extends RegexAttackDetector {

    private static final String SCHEME = "(?:https?|ftps?)://(?:[^/\\s@?#]*@)?";

    private static final String INTERNAL_HOST = "(?:"
            + "localhost|[\\w-]+\\.localhost"
            + "|127(?:\\.\\d{1,3}){3}"
            + "|0\\.0\\.0\\.0|0"
            + "|\\[(?:::1?|::ffff:[0-9a-f:.]+|fe80[0-9a-f:]*|f[cd][0-9a-f:]*)\\]"
            + "|169\\.254(?:\\.\\d{1,3}){2}"
            + "|10(?:\\.\\d{1,3}){3}"
            + "|192\\.168(?:\\.\\d{1,3}){2}"
            + "|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}"
            + "|metadata\\.google\\.internal|[\\w.-]+\\.internal"
            + "|\\d{8,10}"                                   // decimal IP: 2130706433
            + "|0x[0-9a-f]{6,8}"                             // hex IP: 0x7f000001
            + "|0[0-7]{1,3}(?:\\.0?[0-7]{1,3}){3}"           // octal IP: 0177.0.0.1
            + ")";

    private static final List<Rule> RULES = List.of(
            // http://127.0.0.1/  http://localhost:8080  http://user@10.0.0.5/
            rule(SCHEME + INTERNAL_HOST + "(?::\\d+)?(?:[/?#\\s]|$)", "://"),
            // Cloud metadata endpoints, with or without a scheme
            rule("169\\.254\\.169\\.254", "169.254.169.254"),
            rule("metadata\\.google\\.internal", "metadata.google.internal"),
            rule("/latest/meta-data", "/latest/meta-data"),
            rule("/computemetadata/v1", "/computemetadata/v1"),
            // Schemes that exist to talk to internal services
            rule("\\b(?:gopher|dict|tftp|ldaps?|sftp|netdoc)://", "://")
    );

    public SsrfDetector() {
        super(RULES);
    }

    @Override
    public boolean appliesToHeaders() {
        return false;
    }

    @Override
    public AttackType type() {
        return AttackType.SSRF;
    }
}
