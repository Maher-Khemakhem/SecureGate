package com.securegate.filter;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class RequestPathsTest {

    @ParameterizedTest
    @CsvSource({
            "/admin/config,              /admin/config",
            "/%61dmin/config,            /admin/config",      // percent-encoded letter
            "/admin;x=1/config,          /admin/config",      // path parameter
            "/admin;jsessionid=ab/x,     /admin/x",
            "//admin//config,            /admin/config",      // repeated slashes
            "/./admin/./config,          /admin/config",      // dot segments
            "/x/../admin/config,         /admin/config",      // parent segments
            "/../../admin,               /admin",             // cannot escape root
            "/%2e%2e/admin,              /admin",             // encoded dots
            "/api/search?q=1,            /api/search",        // query removed
            "/dashboard/,                /dashboard/",        // trailing slash kept
            "/,                          /",
            "'',                         /",
            "/caf%C3%A9,                 /café",              // UTF-8 decoding
            "/a+b,                       /a+b"                // '+' is literal in paths
    })
    void canonicalisesLikeTheContainer(String raw, String expected) {
        assertThat(RequestPaths.canonical(raw)).isEqualTo(expected);
    }
}
