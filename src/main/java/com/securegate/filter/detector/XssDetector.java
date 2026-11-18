package com.securegate.filter.detector;

import com.securegate.model.AttackType;

import java.util.List;

/**
 * Signature-based cross-site scripting detection (OWASP A03:2021 Injection).
 */
public class XssDetector extends RegexAttackDetector {

    private static final String EVENT_HANDLERS =
            "error|load|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|mousedown|mouseup|mousemove"
                    + "|focus|blur|focusin|focusout|submit|change|input|keydown|keyup|keypress|toggle|resize|scroll"
                    + "|animationstart|animationend|transitionend|pointerover|pointerdown|pointerenter|begin|end"
                    + "|wheel|copy|paste|cut|drag|dragstart|drop|beforeunload|unload|hashchange|message|show|abort";

    private static final List<String> PATTERNS = List.of(
            // <script ...> and </script>
            "<\\s*/?\\s*script\\b",
            // Dangerous URL schemes (allow whitespace/control chars inside, as browsers do)
            "j\\s*a\\s*v\\s*a\\s*s\\s*c\\s*r\\s*i\\s*p\\s*t\\s*:",
            "\\bvbscript\\s*:",
            "\\bdata\\s*:\\s*text/html",
            // Inline event handlers: onerror=, onload = ...
            "\\bon(?:" + EVENT_HANDLERS + ")\\s*=",
            // Any on*= attribute inside something that looks like a tag
            "<[a-z!/][^>]*\\son[a-z]+\\s*=",
            // Elements commonly used to load or run active content
            "<\\s*(?:iframe|frame|frameset|object|embed|applet|meta|base|link|svg|math|isindex)\\b",
            "<\\s*img\\b[^>]*\\bsrc\\s*=",
            // DOM sinks / script gadgets
            "\\bdocument\\s*\\.\\s*(?:cookie|domain|write|location)\\b",
            "\\bwindow\\s*\\.\\s*location\\b",
            "\\beval\\s*\\(",
            "\\balert\\s*[(`]",
            "\\bsrcdoc\\s*=",
            "\\bstyle\\s*=[^>]*expression\\s*\\("
    );

    public XssDetector() {
        super(PATTERNS);
    }

    @Override
    public AttackType type() {
        return AttackType.XSS;
    }
}
