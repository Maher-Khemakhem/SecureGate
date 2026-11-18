package com.securegate.controller;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Intentionally naive endpoints used as attack targets. They do no validation
 * or escaping of their own; all protection comes from the SecureGate filters.
 * <p>
 * They only simulate the dangerous behaviour (string-built SQL, raw file
 * paths, unescaped HTML) and never touch a real database or the filesystem,
 * so the demo stays safe even with {@code securegate.enabled=false}.
 */
@RestController
@RequestMapping("/api")
@Profile("demo")
public class DemoController {

    /** SQLi / XSS target: echoes the query into a hand-built SQL string. */
    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam(defaultValue = "") String q) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("query", q);
        body.put("executed_sql", "SELECT * FROM products WHERE name LIKE '%" + q + "%'");
        body.put("results", List.of("Product matching '" + q + "'"));
        return body;
    }

    /** Path traversal target: pretends to read a file under /var/app/files. */
    @GetMapping("/file")
    public Map<String, Object> file(@RequestParam String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("requested_path", "/var/app/files/" + path);
        body.put("content", "(simulated) contents of " + path);
        return body;
    }

    /** Stored-XSS target: accepts a comment and returns it as raw HTML. */
    @PostMapping("/comment")
    public Map<String, Object> comment(@RequestBody Map<String, Object> request) {
        Object text = request.getOrDefault("text", "");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("saved", true);
        body.put("html", "<div class=\"comment\">" + text + "</div>");
        body.put("created_at", Instant.now().toString());
        return body;
    }
}
