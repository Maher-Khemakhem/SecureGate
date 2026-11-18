package com.securegate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gateway mode against a stub upstream app (JDK HttpServer) that echoes what it receives.
 */
@SpringBootTest(properties = {
        "securegate.admin.token=test-token",
        "securegate.max-body-size=1024",
        "securegate.rate-limit.max-requests=50",
        "securegate.blocking.max-violations=50",
        "securegate.alerts.log-file=target/test-logs/gateway-alerts.json"
})
@AutoConfigureMockMvc
class GatewayIntegrationTest {

    private static final AtomicInteger UPSTREAM_CALLS = new AtomicInteger();
    private static final HttpServer UPSTREAM = startUpstream();

    @DynamicPropertySource
    static void upstream(DynamicPropertyRegistry registry) {
        registry.add("securegate.proxy.target-url", () -> "http://localhost:" + UPSTREAM.getAddress().getPort());
    }

    @AfterAll
    static void stop() {
        UPSTREAM.stop(0);
    }

    @Autowired
    private MockMvc mvc;

    @BeforeEach
    void reset() {
        UPSTREAM_CALLS.set(0);
    }

    private static RequestPostProcessor ip(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    @Test
    void cleanRequestIsForwardedAndResponseRelayed() throws Exception {
        mvc.perform(get("/api/products").queryParam("q", "laptop").with(ip("10.2.0.1")))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Upstream", "stub"))
                .andExpect(content().string(containsString("method=GET")))
                .andExpect(content().string(containsString("path=/api/products")))
                .andExpect(content().string(containsString("query=q=laptop")));
        assertThat(UPSTREAM_CALLS).hasValue(1);
    }

    @Test
    void attackIsBlockedAndNeverReachesUpstream() throws Exception {
        mvc.perform(get("/api/products").queryParam("q", "' OR 1=1 --").with(ip("10.2.0.2")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("SQLi detected"));
        mvc.perform(post("/api/comments").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"<script>alert(1)</script>\"}").with(ip("10.2.0.2")))
                .andExpect(status().isBadRequest());
        assertThat(UPSTREAM_CALLS).hasValue(0);
    }

    @Test
    void jsonBodyIsForwardedIntact() throws Exception {
        mvc.perform(post("/api/comments").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"Nice article\"}").with(ip("10.2.0.3")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("method=POST")))
                .andExpect(content().string(containsString("body={\"text\":\"Nice article\"}")));
    }

    @Test
    void formBodyIsInspectedAndForwarded() throws Exception {
        mvc.perform(post("/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("user=alice&pass=s3cret").with(ip("10.2.0.4")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("body=user=alice&pass=s3cret")));

        mvc.perform(post("/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("user=admin%27--&pass=x").with(ip("10.2.0.4")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("SQLi detected"));
    }

    @Test
    void upstreamReceivesTheCanonicalPathThatWasInspected() throws Exception {
        mvc.perform(get(URI.create("/api/a;jsessionid=x/%62")).with(ip("10.2.0.5")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("path=/api/a/b\n")));
    }

    @Test
    void forwardingHeadersAreSetAndSpoofedOnesReplaced() throws Exception {
        mvc.perform(get("/whoami").header("X-Forwarded-For", "1.2.3.4").with(ip("10.2.0.6")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("xff=10.2.0.6\n")))
                .andExpect(content().string(containsString("real-ip=10.2.0.6\n")));
    }

    @Test
    void adminTokenIsNeverLeakedUpstream() throws Exception {
        mvc.perform(get("/whoami").header("X-Admin-Token", "test-token").with(ip("10.2.0.7")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("admin-token=null")));
    }

    @Test
    void adminApiAndDashboardStayLocal() throws Exception {
        mvc.perform(get("/admin/config").header("X-Admin-Token", "test-token").with(ip("10.2.0.8")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("gateway"));
        mvc.perform(get("/dashboard/index.html").with(ip("10.2.0.8")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("SecureGate Console")));
        assertThat(UPSTREAM_CALLS).hasValue(0);
    }

    @Test
    void upstreamStatusAndRedirectsPassThrough() throws Exception {
        mvc.perform(get("/missing").with(ip("10.2.0.9")))
                .andExpect(status().isNotFound());
        mvc.perform(get("/redirect").with(ip("10.2.0.9")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/next"))
                .andExpect(header().string("Location", not(containsString("localhost"))));
    }

    // ---------------------------------------------------------------- stub upstream

    private static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/", GatewayIntegrationTest::echo);
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void echo(HttpExchange exchange) throws IOException {
        UPSTREAM_CALLS.incrementAndGet();
        String path = exchange.getRequestURI().getRawPath();
        if (path.equals("/missing")) {
            send(exchange, 404, "not found");
            return;
        }
        if (path.equals("/redirect")) {
            exchange.getResponseHeaders().add("Location",
                    "http://localhost:" + UPSTREAM.getAddress().getPort() + "/next");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
            return;
        }
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        var h = exchange.getRequestHeaders();
        String text = "method=" + exchange.getRequestMethod() + "\n"
                + "path=" + path + "\n"
                + "query=" + exchange.getRequestURI().getRawQuery() + "\n"
                + "xff=" + h.getFirst("X-Forwarded-For") + "\n"
                + "real-ip=" + h.getFirst("X-Real-IP") + "\n"
                + "admin-token=" + h.getFirst("X-Admin-Token") + "\n"
                + "body=" + body + "\n";
        send(exchange, 200, text);
    }

    private static void send(HttpExchange exchange, int status, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("X-Upstream", "stub");
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
