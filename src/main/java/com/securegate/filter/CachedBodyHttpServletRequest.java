package com.securegate.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Request wrapper that replays an already-read body, so the filter can inspect
 * it and the controller (or the reverse proxy) can still consume it.
 * <p>
 * Because the original stream has been read, the container can no longer parse
 * form fields from it, so this wrapper parses query and form-urlencoded
 * parameters itself from the cached bytes.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] body;
    private Map<String, String[]> parameters;

    public CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    public byte[] getBody() {
        return body;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream in = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return in.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException("Async reads are not supported");
            }

            @Override
            public int read() {
                return in.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return in.read(b, off, len);
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), charset()));
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }

    // ---------------------------------------------------------------- parameters

    @Override
    public Map<String, String[]> getParameterMap() {
        if (parameters == null) {
            // The container still parses the query string; it can no longer read form
            // fields from the consumed body, so those are parsed from the cached bytes.
            Map<String, String[]> container = super.getParameterMap();
            Map<String, List<String>> merged = new LinkedHashMap<>();
            addAll(merged, container);
            if (isFormUrlEncoded()) {
                Map<String, String[]> form = parseQuery(new String(body, charset()), charset());
                if (!alreadyContains(container, form)) {
                    addAll(merged, form);
                }
            }
            Map<String, String[]> result = new LinkedHashMap<>();
            merged.forEach((k, v) -> result.put(k, v.toArray(String[]::new)));
            parameters = Collections.unmodifiableMap(result);
        }
        return parameters;
    }

    @Override
    public String getParameter(String name) {
        String[] values = getParameterMap().get(name);
        return values == null || values.length == 0 ? null : values[0];
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = getParameterMap().get(name);
        return values == null ? null : values.clone();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(getParameterMap().keySet());
    }

    /** Parses {@code a=1&b=2&a=3} with form decoding ('+' is a space). Malformed escapes are kept raw. */
    public static Map<String, String[]> parseQuery(String query, Charset charset) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String key = decode(eq < 0 ? pair : pair.substring(0, eq), charset);
                String value = eq < 0 ? "" : decode(pair.substring(eq + 1), charset);
                values.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            }
        }
        Map<String, String[]> result = new LinkedHashMap<>();
        values.forEach((k, v) -> result.put(k, v.toArray(String[]::new)));
        return result;
    }

    /** Some containers (e.g. the MockMvc test request) expose form fields as parameters up front. */
    private static boolean alreadyContains(Map<String, String[]> container, Map<String, String[]> form) {
        if (form.isEmpty()) {
            return true;
        }
        for (Map.Entry<String, String[]> e : form.entrySet()) {
            String[] existing = container.get(e.getKey());
            if (existing == null || !List.of(existing).containsAll(List.of(e.getValue()))) {
                return false;
            }
        }
        return true;
    }

    private static void addAll(Map<String, List<String>> target, Map<String, String[]> source) {
        source.forEach((k, v) -> target.computeIfAbsent(k, x -> new ArrayList<>()).addAll(List.of(v)));
    }

    private static String decode(String s, Charset charset) {
        try {
            return URLDecoder.decode(s, charset);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private boolean isFormUrlEncoded() {
        String ct = getContentType();
        return ct != null && ct.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded");
    }

    private Charset charset() {
        String enc = getCharacterEncoding();
        try {
            return enc != null ? Charset.forName(enc) : StandardCharsets.UTF_8;
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }
}
