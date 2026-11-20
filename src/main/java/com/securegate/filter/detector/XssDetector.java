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

    private static final List<Rule> RULES = List.of(
            // <script ...> and </script>
            rule("<\\s*/?\\s*script\\b", "script"),
            // Dangerous URL schemes (allow whitespace/control chars inside, as browsers do)
            rule("j\\s*a\\s*v\\s*a\\s*s\\s*c\\s*r\\s*i\\s*p\\s*t\\s*:", ":"),
            rule("\\bvbscript\\s*:", "vbscript"),
            rule("\\bdata\\s*:\\s*text/html", "data"),
            // Inline event handlers: onerror=, onload = ...
            rule("\\bon(?:" + EVENT_HANDLERS + ")\\s*=", "="),
            // Any on*= attribute inside something that looks like a tag
            rule("<[a-z!/][^>]*\\son[a-z]+\\s*=", "<"),
            // Elements commonly used to load or run active content
            rule("<\\s*(?:iframe|frame|frameset|object|embed|applet|meta|base|link|svg|math|isindex)\\b", "<"),
            rule("<\\s*img\\b[^>]*\\bsrc\\s*=", "<"),
            // DOM sinks / script gadgets
            rule("\\bdocument\\s*\\.\\s*(?:cookie|domain|write|location)\\b", "document"),
            rule("\\bwindow\\s*\\.\\s*location\\b", "window"),
            rule("\\beval\\s*\\(", "eval"),
            rule("\\balert\\s*[(`]", "alert"),
            rule("\\bsrcdoc\\s*=", "srcdoc"),
            rule("\\bstyle\\s*=[^>]*expression\\s*\\(", "expression")
    );

    public XssDetector() {
        super(RULES);
    }

    @Override
    public AttackType type() {
        return AttackType.XSS;
    }
}
