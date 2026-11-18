package com.securegate;

import com.securegate.service.AlertLoggerService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.net.URI;
import java.nio.file.Files;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end checks of the whole filter chain through MockMvc.
 * Each test uses its own client IP so rate limits and blocks don't interfere.
 */
@SpringBootTest(properties = {
        "securegate.admin.token=test-token",
        "securegate.max-body-size=1024",
        "securegate.rate-limit.max-requests=5",
        "securegate.rate-limit.window-seconds=60",
        "securegate.blocking.max-violations=3",
        "securegate.alerts.log-file=target/test-logs/alerts.json"
})
@AutoConfigureMockMvc
@ActiveProfiles(SecureGateApplication.DEMO_PROFILE)
class SecureGateIntegrationTest {

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

    private static MockHttpServletRequestBuilder admin(MockHttpServletRequestBuilder builder) {
        return builder.header("X-Admin-Token", "test-token");
    }

    @Test
    void benignRequestPasses() throws Exception {
        mvc.perform(get("/api/search").param("q", "laptop").with(ip("10.0.0.1")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.query").value("laptop"));
    }

    @Test
    void sqlInjectionInQueryParamIsBlocked() throws Exception {
        mvc.perform(get("/api/search").param("q", "' OR 1=1 --").with(ip("10.0.0.2")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.blocked").value(true))
                .andExpect(jsonPath("$.reason").value("SQLi detected"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void xssInQueryParamIsBlocked() throws Exception {
        mvc.perform(get("/api/search").param("q", "<script>alert(1)</script>").with(ip("10.0.0.3")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("XSS detected"));
    }

    @Test
    void pathTraversalIsBlocked() throws Exception {
        mvc.perform(get("/api/file").param("path", "../../etc/passwd").with(ip("10.0.0.4")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("Path traversal detected"));
    }

    @Test
    void xssInJsonBodyIsBlockedAndBenignBodyReachesController() throws Exception {
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"<img src=x onerror=alert(1)>\"}").with(ip("10.0.0.5")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("XSS detected"));

        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"Nice article!\"}").with(ip("10.0.0.5")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.html").value(containsString("Nice article!")));
    }

    @Test
    void oversizedBodyIsBlocked() throws Exception {
        String big = "{\"text\":\"" + "a".repeat(2000) + "\"}";
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON).content(big)
                        .with(ip("10.0.0.6")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("Payload too large"));
    }

    @Test
    void attackInHeaderIsBlocked() throws Exception {
        mvc.perform(get("/api/search").param("q", "ok").header("X-Custom", "1' UNION SELECT password FROM users--")
                        .with(ip("10.0.0.7")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("SQLi detected"));
    }

    @Test
    void rateLimitReturns429AfterMaxRequests() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(get("/api/search").param("q", "x").with(ip("10.0.1.1")))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/api/search").param("q", "x").with(ip("10.0.1.1")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.reason").value("Rate limit exceeded"));
    }

    @Test
    void repeatedViolationsBlockIpAndAdminCanUnblock() throws Exception {
        String attacker = "10.0.2.1";
        for (int i = 0; i < 3; i++) {
            mvc.perform(get("/api/search").param("q", "' OR 1=1").with(ip(attacker)))
                    .andExpect(status().isBadRequest());
        }
        // Even a clean request is now refused
        mvc.perform(get("/api/search").param("q", "laptop").with(ip(attacker)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("IP address is blocked"));

        mvc.perform(admin(get("/admin/blocked-ips")).with(ip("10.0.9.9")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked_ips[?(@.ip == '" + attacker + "')]").exists());

        // Admin calls still work from the blocked IP itself, so operators can't lock themselves out
        mvc.perform(admin(delete("/admin/blocked-ips/" + attacker)).with(ip(attacker)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.unblocked").value(true));

        mvc.perform(get("/api/search").param("q", "laptop").with(ip(attacker)))
                .andExpect(status().isOk());
    }

    @Test
    void configReportsLimitsAndCallerIp() throws Exception {
        mvc.perform(admin(get("/admin/config")).with(ip("10.0.5.1")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.your_ip").value("10.0.5.1"))
                .andExpect(jsonPath("$.rate_limit.max_requests").value(5))
                .andExpect(jsonPath("$.blocking.max_violations").value(3))
                .andExpect(jsonPath("$.max_body_size").value(1024));
    }

    @Test
    void adminCanBlockIpManually() throws Exception {
        mvc.perform(admin(post("/admin/blocked-ips")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ip\":\"10.0.6.1\"}").with(ip("10.0.9.9")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.entry.ip").value("10.0.6.1"));
        mvc.perform(get("/api/search").param("q", "laptop").with(ip("10.0.6.1")))
                .andExpect(status().isForbidden());

        mvc.perform(admin(post("/admin/blocked-ips")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ip\":\"not an ip\"}").with(ip("10.0.9.9")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void dashboardPageLoadsEvenForBlockedIp() throws Exception {
        mvc.perform(admin(post("/admin/blocked-ips")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ip\":\"10.0.7.1\"}").with(ip("10.0.9.9")))
                .andExpect(status().isCreated());

        mvc.perform(get("/dashboard").with(ip("10.0.7.1")))
                .andExpect(status().is3xxRedirection());
        mvc.perform(get("/dashboard/").with(ip("10.0.7.1")))
                .andExpect(status().isOk());
        mvc.perform(get("/dashboard/index.html").with(ip("10.0.7.1")))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                        .string(containsString("SecureGate Console")));
    }

    /** Regression: these raw paths used to skip the token check while still routing to /admin/config. */
    @ParameterizedTest
    @ValueSource(strings = {"/%61dmin/config", "/admin;x=1/config", "/ADMIN/config", "/admin//config",
            "/./admin/config", "/admin/./config"})
    void adminAuthCannotBeBypassedWithPathTricks(String rawPath) throws Exception {
        mvc.perform(get(URI.create(rawPath)).with(ip("10.0.3.2")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpointsRequireToken() throws Exception {
        mvc.perform(get("/admin/alerts").with(ip("10.0.3.1")))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/alerts").header("X-Admin-Token", "wrong").with(ip("10.0.3.1")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void alertsAreWrittenAsJsonLinesAndReturnedNewestFirst() throws Exception {
        mvc.perform(get("/api/file").param("path", "..%2F..%2Fetc%2Fpasswd").with(ip("10.0.4.1")))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/search").param("q", "<script>x</script>").with(ip("10.0.4.1")))
                .andExpect(status().isBadRequest());

        assertThat(Files.readAllLines(alertLogger.getLogFile()))
                .anySatisfy(line -> assertThat(line)
                        .contains("\"ip\":\"10.0.4.1\"")
                        .contains("\"attack_type\":\"PATH_TRAVERSAL\"")
                        .contains("\"endpoint\":\"/api/file\"")
                        .contains("\"action\":\"BLOCKED\""));

        mvc.perform(admin(get("/admin/alerts")).with(ip("10.0.9.9")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alerts[0].attack_type").exists())
                .andExpect(jsonPath("$.alerts[?(@.ip == '10.0.4.1' && @.attack_type == 'XSS')]").exists());
    }
}
