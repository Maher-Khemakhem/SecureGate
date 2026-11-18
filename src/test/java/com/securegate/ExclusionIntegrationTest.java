package com.securegate;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.net.URI;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Path exclusions:
 * <ul>
 *   <li>/api/search            full bypass (no blocking, rate limit or detection)</li>
 *   <li>/api/comment           XSS detection skipped, everything else still enforced</li>
 *   <li>/api/file              all detectors skipped</li>
 * </ul>
 */
@SpringBootTest(properties = {
        "securegate.admin.token=test-token",
        "securegate.max-body-size=1024",
        "securegate.rate-limit.max-requests=3",
        "securegate.blocking.max-violations=2",
        "securegate.alerts.log-file=target/test-logs/exclusion-alerts.json",
        "securegate.excluded-paths[0]=/api/search",
        "securegate.excluded-paths[1]=/admin/**",
        "securegate.excluded-paths[2]=/public/**",
        "securegate.detection.exclusions[0].paths[0]=/api/comment",
        "securegate.detection.exclusions[0].types[0]=XSS",
        "securegate.detection.exclusions[1].paths[0]=/api/file"
})
@AutoConfigureMockMvc
@ActiveProfiles(SecureGateApplication.DEMO_PROFILE)
class ExclusionIntegrationTest {

    @Autowired
    private MockMvc mvc;

    private static RequestPostProcessor ip(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    @Test
    void bypassedPathSkipsDetectionRateLimitAndBlocking() throws Exception {
        String client = "10.1.0.1";
        // Far more than the 3 req limit, with attack payloads: all pass
        for (int i = 0; i < 6; i++) {
            mvc.perform(get("/api/search").param("q", "' OR 1=1 --").with(ip(client)))
                    .andExpect(status().isOk());
        }
        // Get the IP blocked via another endpoint...
        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/comment-does-not-exist").param("x", "<script>").with(ip(client)))
                    .andExpect(status().isBadRequest());
        }
        // ...the bypassed path still answers, other paths are denied
        mvc.perform(get("/api/search").param("q", "ok").with(ip(client))).andExpect(status().isOk());
        mvc.perform(get("/api/file").param("path", "a.txt").with(ip(client))).andExpect(status().isForbidden());
    }

    @Test
    void partialExclusionSkipsOnlyTheListedDetector() throws Exception {
        String client = "10.1.0.2";
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"<b>bold</b><script>x</script>\"}").with(ip(client)))
                .andExpect(status().isOk());
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"x' UNION SELECT password FROM users--\"}").with(ip(client)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("SQLi detected"));
    }

    @Test
    void sizeLimitStillAppliesOnExcludedDetectionPaths() throws Exception {
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"" + "a".repeat(2000) + "\"}").with(ip("10.1.0.3")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("Payload too large"));
    }

    @Test
    void exclusionWithoutTypesSkipsAllDetectors() throws Exception {
        mvc.perform(get("/api/file").param("path", "../../etc/passwd").with(ip("10.1.0.4")))
                .andExpect(status().isOk());
    }

    @Test
    void rawPathThatOnlyLooksExcludedIsStillChecked() throws Exception {
        // Raw path starts with the bypassed /public/**, but Tomcat routes it to /api/xyz.
        // Exclusions match the canonical path, so the request is NOT bypassed.
        mvc.perform(get(URI.create("/public/../api/xyz?q=%3Cscript%3E")).with(ip("10.1.0.5")))
                .andExpect(status().isBadRequest());
        mvc.perform(get(URI.create("/public/%2e%2e/api/xyz?q=%3Cscript%3E")).with(ip("10.1.0.7")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void similarLookingPathIsNotExcluded() throws Exception {
        mvc.perform(get("/api/searchx").param("q", "<script>x</script>").with(ip("10.1.0.8")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void excludingAdminPathsNeverDisablesAdminAuth() throws Exception {
        mvc.perform(get("/admin/config").with(ip("10.1.0.6")))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/config").header("X-Admin-Token", "test-token").with(ip("10.1.0.6")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exclusions.bypass_paths[0]").value("/api/search"))
                .andExpect(jsonPath("$.exclusions.detection[0].skips[0]").value("XSS"));
    }
}
