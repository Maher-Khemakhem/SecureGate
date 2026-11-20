package com.securegate.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Replays bytes that were already read from the request, followed by the rest of the
 * original stream. Used in monitor mode for bodies larger than the size limit: the filter
 * has consumed the first bytes to find out the body is too big, but must still let the
 * request through intact.
 */
public class PrefixedBodyRequest extends HttpServletRequestWrapper {

    private final byte[] prefix;
    private final InputStream rest;

    public PrefixedBodyRequest(HttpServletRequest request, byte[] prefix) throws IOException {
        super(request);
        this.prefix = prefix;
        this.rest = request.getInputStream();
    }

    @Override
    public ServletInputStream getInputStream() {
        InputStream joined = new SequenceInputStream(new ByteArrayInputStream(prefix), rest);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                try {
                    return joined.available() == 0 && rest.available() == 0;
                } catch (IOException e) {
                    return true;
                }
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
            public int read() throws IOException {
                return joined.read();
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return joined.read(b, off, len);
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), charset()));
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
