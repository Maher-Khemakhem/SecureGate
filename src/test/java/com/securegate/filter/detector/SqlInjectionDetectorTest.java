package com.securegate.filter.detector;

import com.securegate.model.AttackType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class SqlInjectionDetectorTest {

    private final SqlInjectionDetector detector = new SqlInjectionDetector();

    @ParameterizedTest
    @ValueSource(strings = {
            "' OR 1=1",
            "' OR 1=1 --",
            "admin'--",
            "admin' #",
            "1' or '1'='1",
            "\" or \"a\"=\"a",
            "' AND 1=1",
            "1 OR 1=1",
            "x' UNION SELECT username, password FROM users--",
            "1 union all select null,null",
            "1 UNION/**/SELECT 1",
            "1; DROP TABLE users",
            "'; exec xp_cmdshell 'dir'",
            "1 AND SLEEP(5)",
            "1'; WAITFOR DELAY '0:0:5'--",
            "select table_name from information_schema.tables",
            "1 and @@version",
            "%27%20OR%201%3D1",            // URL-encoded
            "%2527%2520OR%25201%253D1",    // double URL-encoded
            "&#39; OR 1=1",                 // HTML entity
            "' oR 1=1"                      // mixed case
    })
    void detectsSqlInjection(String payload) {
        assertThat(detector.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "laptop",
            "O'Reilly books",
            "rock and roll",
            "select the best product",
            "Tom & Jerry",
            "price >= 10",
            "2024-01-01",
            "one=two",
            "it's raining -- maybe",
            "C# programming"
    })
    void allowsBenignInput(String input) {
        assertThat(detector.detect(input)).as(input).isFalse();
    }

    @Test
    void nullAndEmptyAreSafe() {
        assertThat(detector.detect(null)).isFalse();
        assertThat(detector.detect("")).isFalse();
        assertThat(detector.detect("   ")).isFalse();
    }

    @Test
    void reportsSqliType() {
        assertThat(detector.type()).isEqualTo(AttackType.SQLI);
        assertThat(detector.type().label()).isEqualTo("SQLi");
    }
}
