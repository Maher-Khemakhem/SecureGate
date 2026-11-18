package com.securegate.filter.detector;

import com.securegate.model.AttackType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class XssDetectorTest {

    private final XssDetector detector = new XssDetector();

    @ParameterizedTest
    @ValueSource(strings = {
            "<script>alert(1)</script>",
            "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
            "< script >alert(1)",
            "javascript:alert(document.cookie)",
            "JaVaScRiPt:alert(1)",
            "java\tscript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "\" onmouseover=\"alert(1)",
            "<svg/onload=alert(1)>",
            "<iframe src=\"https://evil.example\"></iframe>",
            "<a href=\"vbscript:msgbox(1)\">x</a>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "<div style=\"width:expression(alert(1))\">",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",       // URL-encoded
            "%253Cscript%253E",                            // double URL-encoded
            "&lt;script&gt;alert(1)&lt;/script&gt;",       // HTML entities
            "&#60;script&#62;",                            // numeric entities
            "<details open ontoggle=alert(1)>",
            "eval(atob('YWxlcnQoMSk='))"
    })
    void detectsXss(String payload) {
        assertThat(detector.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Great product, would buy again!",
            "one=two",
            "money=100",
            "button color: blue",
            "a < b and c > d",
            "https://example.com/page?id=1",
            "I like JavaScript",
            "description: scripting languages",
            "online=true"
    })
    void allowsBenignInput(String input) {
        assertThat(detector.detect(input)).as(input).isFalse();
    }

    @Test
    void reportsXssType() {
        assertThat(detector.type()).isEqualTo(AttackType.XSS);
    }
}
