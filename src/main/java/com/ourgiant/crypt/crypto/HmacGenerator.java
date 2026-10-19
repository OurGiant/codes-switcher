package com.ourgiant.crypt.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HexFormat;

/** Computes HMACs over UTF-8 text with a key given as text, hex or Base64. */
public final class HmacGenerator {

    public enum Algorithm {
        SHA256("HMAC-SHA256", "HmacSHA256"),
        SHA384("HMAC-SHA384", "HmacSHA384"),
        SHA512("HMAC-SHA512", "HmacSHA512"),
        SHA1("HMAC-SHA1 (legacy)", "HmacSHA1");

        private final String label;
        final String jcaName;

        Algorithm(String label, String jcaName) {
            this.label = label;
            this.jcaName = jcaName;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public enum KeyFormat {
        TEXT("Text (UTF-8)"), HEX("Hex"), BASE64("Base64");

        private final String label;

        KeyFormat(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** The MAC in both common renderings. */
    public record Result(String hex, String base64, String base64Url) {
    }

    private HmacGenerator() {
    }

    public static byte[] parseKey(String key, KeyFormat format) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("A key is required");
        }
        try {
            return switch (format) {
                case TEXT -> key.getBytes(StandardCharsets.UTF_8);
                case HEX -> HexFormat.of().parseHex(key.replaceAll("\\s+", ""));
                case BASE64 -> Base64.getMimeDecoder().decode(key.trim().replace('-', '+').replace('_', '/'));
            };
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Key is not valid " + format + ": " + e.getMessage());
        }
    }

    public static Result compute(String message, String key, KeyFormat keyFormat, Algorithm algorithm)
            throws GeneralSecurityException {
        byte[] keyBytes = parseKey(key, keyFormat);
        if (keyBytes.length == 0) {
            throw new IllegalArgumentException("Key decodes to zero bytes");
        }
        Mac mac = Mac.getInstance(algorithm.jcaName);
        mac.init(new SecretKeySpec(keyBytes, algorithm.jcaName));
        byte[] tag = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return new Result(HexFormat.of().formatHex(tag),
                Base64.getEncoder().encodeToString(tag),
                Base64.getUrlEncoder().withoutPadding().encodeToString(tag));
    }
}
