package com.securegate.filter.detector;

import com.securegate.model.AttackType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class PathTraversalDetectorTest {

    private final PathTraversalDetector detector = new PathTraversalDetector();

    @ParameterizedTest
    @ValueSource(strings = {
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "files/../../secret.txt",
            "..%2F..%2Fetc%2Fpasswd",
            "..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",   // double-encoded
            "..%c0%af..%c0%afetc/passwd",       // overlong UTF-8
            "%c0%ae%c0%ae/secret",
            "..%5c..%5cboot.ini",
            "/etc/passwd",
            "/proc/self/environ",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "report.pdf%00.png",                // null byte
            "file:///etc/shadow",
            "..",
            "uploads/.."
    })
    void detectsPathTraversal(String payload) {
        assertThat(detector.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "report.pdf",
            "docs/2024/summary.txt",
            "my.file.name.txt",
            "version 1.2..3",
            "images/logo.png",
            "etc-notes.txt"
    })
    void allowsBenignPaths(String input) {
        assertThat(detector.detect(input)).as(input).isFalse();
    }

    @Test
    void reportsPathTraversalType() {
        assertThat(detector.type()).isEqualTo(AttackType.PATH_TRAVERSAL);
    }
}
