package com.securegate.filter.detector;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Canonicalises untrusted input before pattern matching so that simple
 * encoding tricks (double URL-encoding, HTML entities, mixed case, null bytes,
 * plus-as-space) do not bypass the detectors.
 */
public final class InputNormalizer {

    private static final int MAX_DECODE_ROUNDS = 3;
    private static final Pattern NUMERIC_ENTITY = Pattern.compile("&#(x?)([0-9a-f]+);?", Pattern.CASE_INSENSITIVE);

    private InputNormalizer() {
    }

    public static String normalize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        String value = input;
        for (int i = 0; i < MAX_DECODE_ROUNDS; i++) {
            String decoded = urlDecode(value);
            decoded = decodeHtmlEntities(decoded);
            if (decoded.equals(value)) {
                break;
            }
            value = decoded;
        }
        value = value.replace("\0", "");
        return value.toLowerCase(Locale.ROOT);
    }

    static String urlDecode(String value) {
        if (value.indexOf('%') < 0 && value.indexOf('+') < 0) {
            return value;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Malformed escape (e.g. a lone '%'): decode what we can, character by character.
            return lenientDecode(value);
        }
    }

    private static String lenientDecode(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                int hi = Character.digit(value.charAt(i + 1), 16);
                int lo = Character.digit(value.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    sb.append((char) ((hi << 4) + lo));
                    i += 2;
                    continue;
                }
            }
            sb.append(c == '+' ? ' ' : c);
        }
        return sb.toString();
    }

    static String decodeHtmlEntities(String value) {
        if (value.indexOf('&') < 0) {
            return value;
        }
        String out = value
                .replace("&lt;", "<").replace("&LT;", "<")
                .replace("&gt;", ">").replace("&GT;", ">")
                .replace("&quot;", "\"").replace("&apos;", "'")
                .replace("&colon;", ":").replace("&sol;", "/")
                .replace("&lpar;", "(").replace("&rpar;", ")");
        Matcher m = NUMERIC_ENTITY.matcher(out);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String replacement;
            try {
                int radix = m.group(1).isEmpty() ? 10 : 16;
                int codePoint = Integer.parseInt(m.group(2), radix);
                replacement = Character.isValidCodePoint(codePoint)
                        ? new String(Character.toChars(codePoint))
                        : m.group();
            } catch (NumberFormatException e) {
                replacement = m.group();
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
