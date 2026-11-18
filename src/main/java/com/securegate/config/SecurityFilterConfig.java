package com.securegate.config;

import com.securegate.controller.AdminController;
import com.securegate.filter.AdminAuthFilter;
import com.securegate.filter.AttackDetectionFilter;
import com.securegate.filter.IpBlockingFilter;
import com.securegate.filter.PathExclusions;
import com.securegate.filter.RateLimitFilter;
import com.securegate.filter.ReverseProxyFilter;
import com.securegate.filter.detector.AttackDetector;
import com.securegate.filter.detector.PathTraversalDetector;
import com.securegate.filter.detector.SqlInjectionDetector;
import com.securegate.filter.detector.XssDetector;
import com.securegate.service.AlertLoggerService;
import com.securegate.service.IpBlockingService;
import com.securegate.service.RateLimiterService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Clock;
import java.util.List;

/**
 * Wires the SecureGate filter chain. Registered as a Spring Boot
 * auto-configuration (see META-INF/spring/...AutoConfiguration.imports), so any
 * Spring Boot app gets the middleware just by adding this jar as a dependency.
 *
 * <pre>
 * order  filter                 response on failure
 * -----  ---------------------  -------------------
 *   1    AdminAuthFilter        401 (only /admin/**)
 *   2    IpBlockingFilter       403
 *   3    RateLimitFilter        429
 *   4    AttackDetectionFilter  400
 * </pre>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "securegate", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SecurityProperties.class)
@EnableScheduling
public class SecurityFilterConfig {

    private static final int BASE_ORDER = Ordered.HIGHEST_PRECEDENCE + 10;

    @Bean
    @ConditionalOnMissingBean(name = "secureGateClock")
    public Clock secureGateClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimiterService rateLimiterService(SecurityProperties properties, Clock secureGateClock) {
        return new RateLimiterService(properties, secureGateClock);
    }

    @Bean
    @ConditionalOnMissingBean
    public IpBlockingService ipBlockingService(SecurityProperties properties, Clock secureGateClock) {
        return new IpBlockingService(properties, secureGateClock);
    }

    @Bean
    @ConditionalOnMissingBean
    public AlertLoggerService alertLoggerService(SecurityProperties properties, Clock secureGateClock) {
        return new AlertLoggerService(properties, secureGateClock);
    }

    /**
     * Exposes the admin API in consumer apps. Skipped when the controller was
     * already picked up by component scanning (as in the bundled demo app).
     */
    @Bean
    @ConditionalOnMissingBean
    public AdminController adminController(IpBlockingService blocking, AlertLoggerService alerts,
                                           SecurityProperties properties) {
        return new AdminController(blocking, alerts, properties);
    }

    /** Serves the monitoring UI (static/dashboard/index.html) at /dashboard. */
    @Bean
    public WebMvcConfigurer secureGateDashboardRoutes() {
        return new WebMvcConfigurer() {
            @Override
            public void addViewControllers(ViewControllerRegistry registry) {
                registry.addRedirectViewController("/dashboard", "/dashboard/");
                registry.addViewController("/dashboard/").setViewName("forward:/dashboard/index.html");
            }
        };
    }

    @Bean
    public SqlInjectionDetector sqlInjectionDetector() {
        return new SqlInjectionDetector();
    }

    @Bean
    public XssDetector xssDetector() {
        return new XssDetector();
    }

    @Bean
    public PathTraversalDetector pathTraversalDetector() {
        return new PathTraversalDetector();
    }

    @Bean
    public FilterRegistrationBean<AdminAuthFilter> secureGateAdminAuthFilter(SecurityProperties properties) {
        return register(new AdminAuthFilter(properties), "secureGateAdminAuthFilter", 1);
    }

    /** Validated at startup: a bad pattern or exclusion type fails fast. */
    @Bean
    @ConditionalOnMissingBean
    public PathExclusions secureGatePathExclusions(SecurityProperties properties) {
        return new PathExclusions(properties);
    }

    @Bean
    public FilterRegistrationBean<IpBlockingFilter> secureGateIpBlockingFilter(
            SecurityProperties properties, IpBlockingService blocking, AlertLoggerService alerts,
            PathExclusions exclusions) {
        return register(new IpBlockingFilter(properties, blocking, alerts, exclusions),
                "secureGateIpBlockingFilter", 2);
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> secureGateRateLimitFilter(
            SecurityProperties properties, RateLimiterService limiter, IpBlockingService blocking,
            AlertLoggerService alerts, PathExclusions exclusions) {
        return register(new RateLimitFilter(properties, limiter, blocking, alerts, exclusions),
                "secureGateRateLimitFilter", 3);
    }

    @Bean
    public FilterRegistrationBean<AttackDetectionFilter> secureGateAttackDetectionFilter(
            SecurityProperties properties, List<AttackDetector> detectors, IpBlockingService blocking,
            AlertLoggerService alerts, PathExclusions exclusions) {
        return register(new AttackDetectionFilter(properties, detectors, blocking, alerts, exclusions),
                "secureGateAttackDetectionFilter", 4);
    }

    /**
     * Gateway mode: registered only when securegate.proxy.target-url is set. It runs
     * after every security filter, so only clean requests are forwarded.
     */
    @Bean
    @ConditionalOnExpression("!'${securegate.proxy.target-url:}'.isBlank()")
    public FilterRegistrationBean<ReverseProxyFilter> secureGateReverseProxyFilter(SecurityProperties properties) {
        return register(new ReverseProxyFilter(properties), "secureGateReverseProxyFilter", 5);
    }

    private static <T extends jakarta.servlet.Filter> FilterRegistrationBean<T> register(T filter, String name,
                                                                                         int position) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setName(name);
        registration.addUrlPatterns("/*");
        registration.setOrder(BASE_ORDER + position);
        return registration;
    }
}
