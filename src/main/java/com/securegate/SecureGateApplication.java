package com.securegate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo application. The middleware itself is wired by
 * {@link com.securegate.config.SecurityFilterConfig}, which is registered as a
 * Spring Boot auto-configuration so any app that depends on this jar gets it.
 * <p>
 * The demo runs with the {@code demo} profile, which loads
 * {@code application-demo.yml} and enables the vulnerable DemoController.
 * Apps that use SecureGate as a library never activate that profile, so
 * neither leaks into them.
 */
@SpringBootApplication
public class SecureGateApplication {

    public static final String DEMO_PROFILE = "demo";

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(SecureGateApplication.class);
        app.setAdditionalProfiles(DEMO_PROFILE);
        app.run(args);
    }
}
