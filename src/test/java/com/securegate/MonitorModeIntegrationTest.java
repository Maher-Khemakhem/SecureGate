package com.securegate;

import com.securegate.service.AlertLoggerService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.file.Files;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Monitor mode: everything is detected and logged as DETECTED, but nothing is blocked and no
 * automatic IP block is created. The mode can be switched at runtime through the admin API.
 */
@SpringBootTest(properties = {
        "securegate.mode=MONITOR",
        "securegate.admin.token=test-token",
        "securegate.max-body-size=1024",
        "securegate.rate-limit.max-requests=3",
        "securegate.blocking.max-violations=2",
        "securegate.alerts.log-file=target/test-logs/monitor-alerts.json"
})
@AutoConfigureMockMvc
@ActiveProfiles(SecureGateApplication.DEMO_PROFILE)
class MonitorModeIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AlertLoggerService alertLogger;

    private static RequestPostProcessor ip(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    /** Other tests in this class switch modes; always end in MONITOR so test order doesn't matter. */
    @AfterEach
    void backToMonitor() throws Exception {
        setMode("MONITOR");
    }

    private void setMode(String mode) throws Exception {
        mvc.perform(put("/admin/mode").header("X-Admin-Token", "test-token")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"mode\":\"" + mode + "\"}")
                        .with(ip("10.9.9.9")))
                .andExpect(status().isOk());
    }

    private boolean logged(String ip, String attackType, String action) {
        return alertLogger.recent(500).stream().anyMatch(a ->
                a.ip().equals(ip) && a.attackType().equals(attackType) && a.action().equals(action));
    }

    @Test
    void attacksPassThroughAndAreLoggedAsDetected() throws Exception {
        String client = "10.8.0.1";
        mvc.perform(get("/api/search").queryParam("q", "' OR 1=1 --").with(ip(client)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.query").value("' OR 1=1 --"));   // the app really received the attack
        mvc.perform(get("/api/search").queryParam("q", "<script>alert(1)</script>").with(ip(client)))
                .andExpect(status().isOk());

        assertThat(logged(client, "SQLi", "DETECTED")).isTrue();
        assertThat(logged(client, "XSS", "DETECTED")).isTrue();
        assertThat(logged(client, "SQLi", "BLOCKED")).isFalse();
    }

    @Test
    void noAutomaticIpBlockIsCreatedNoMatterHowManyAttacks() throws Exception {
        String client = "10.8.0.2";
        for (int i = 0; i < 6; i++) {          // threshold is 2
            mvc.perform(get("/api/file").queryParam("path", "../../etc/passwd").with(ip(client)))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/api/search").queryParam("q", "laptop").with(ip(client))).andExpect(status().isOk());
        mvc.perform(get("/admin/blocked-ips").header("X-Admin-Token", "test-token").with(ip("10.9.9.9")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked_ips[?(@.ip == '" + client + "')]").isEmpty());
    }

    @Test
    void rateLimitHitsAreLoggedButNotRejected() throws Exception {
        String client = "10.8.0.3";
        for (int i = 0; i < 6; i++) {          // limit is 3
            mvc.perform(get("/api/search").queryParam("q", "x").with(ip(client))).andExpect(status().isOk());
        }
        assertThat(logged(client, "RATE_LIMIT", "DETECTED")).isTrue();
    }

    @Test
    void oversizedBodyIsLoggedAndStillReachesTheAppIntact() throws Exception {
        String client = "10.8.0.4";
        String text = "a".repeat(2000);                               // limit is 1024
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"" + text + "\"}").with(ip(client)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.html").value(containsString(text)));
        assertThat(logged(client, "OVERSIZED_PAYLOAD", "DETECTED")).isTrue();
    }

    @Test
    void attackInJsonBodyIsDetectedAndBodyIsForwarded() throws Exception {
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"<img src=x onerror=alert(1)>\"}").with(ip("10.8.0.5")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.html").value(containsString("onerror")));
        assertThat(logged("10.8.0.5", "XSS", "DETECTED")).isTrue();
    }

    @Test
    void modeCanBeSwitchedAtRuntime() throws Exception {
        String client = "10.8.0.6";
        mvc.perform(get("/admin/mode").header("X-Admin-Token", "test-token").with(ip("10.9.9.9")))
                .andExpect(jsonPath("$.enforcement").value("MONITOR"));

        setMode("ENFORCE");
        mvc.perform(get("/api/search").queryParam("q", "' OR 1=1 --").with(ip(client)))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/admin/config").header("X-Admin-Token", "test-token").with(ip("10.9.9.9")))
                .andExpect(jsonPath("$.enforcement").value("ENFORCE"));

        setMode("MONITOR");
        mvc.perform(get("/api/search").queryParam("q", "' OR 1=1 --").with(ip(client)))
                .andExpect(status().isOk());
    }

    @Test
    void invalidModeIsRejected() throws Exception {
        mvc.perform(put("/admin/mode").header("X-Admin-Token", "test-token")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"mode\":\"OFF\"}").with(ip("10.9.9.9")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void modeEndpointRequiresAdminToken() throws Exception {
        mvc.perform(put("/admin/mode").contentType(MediaType.APPLICATION_JSON).content("{\"mode\":\"ENFORCE\"}")
                        .with(ip("10.8.0.7")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void alertFileContainsDetectedLines() throws Exception {
        mvc.perform(get("/api/search").queryParam("q", "1 UNION SELECT a,b FROM t").with(ip("10.8.0.8")))
                .andExpect(status().isOk());
        List<String> lines = Files.readAllLines(alertLogger.getLogFile());
        assertThat(lines).anySatisfy(l -> assertThat(l)
                .contains("\"ip\":\"10.8.0.8\"").contains("\"attack_type\":\"SQLi\"").contains("\"action\":\"DETECTED\""));
    }
}
