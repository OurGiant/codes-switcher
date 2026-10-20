package com.ourgiant.crypt.gpg;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** One primary key from {@code gpg --list-keys --with-colons}. */
public record GpgKey(
        boolean secret,
        String keyId,
        String fingerprint,
        String algorithm,
        int bits,
        Instant created,
        Instant expires,      // null = never
        String validity,      // gpg validity letter: u=ultimate, f=full, m=marginal, -/q=unknown, e=expired, r=revoked
        String capabilities,  // e.g. "scESC"
        List<String> userIds) {

    public boolean canEncrypt() {
        return capabilities.toUpperCase().contains("E");
    }

    public boolean canSign() {
        return capabilities.toUpperCase().contains("S");
    }

    public boolean expired() {
        return "e".equals(validity) || (expires != null && expires.isBefore(Instant.now()));
    }

    public boolean revoked() {
        return "r".equals(validity);
    }

    public String primaryUserId() {
        return userIds.isEmpty() ? "(no user ID)" : userIds.get(0);
    }

    /** Parses the colon-delimited listing (see doc/DETAILS in the GnuPG source). */
    public static List<GpgKey> parseColons(String listing) {
        List<GpgKey> keys = new ArrayList<>();
        Builder current = null;
        boolean expectPrimaryFpr = false;
        for (String line : listing.split("\\r?\\n")) {
            String[] f = line.split(":", -1);
            if (f.length < 2) {
                continue;
            }
            switch (f[0]) {
                case "pub", "sec" -> {
                    if (current != null) {
                        keys.add(current.build());
                    }
                    current = new Builder();
                    current.secret = f[0].equals("sec");
                    current.validity = field(f, 1);
                    current.bits = parseInt(field(f, 2));
                    current.algorithm = algorithmName(field(f, 3), field(f, 16));
                    current.keyId = field(f, 4);
                    current.created = epoch(field(f, 5));
                    current.expires = epoch(field(f, 6));
                    current.capabilities = field(f, 11);
                    expectPrimaryFpr = true;
                }
                case "fpr" -> {
                    if (current != null && expectPrimaryFpr) {
                        current.fingerprint = field(f, 9);
                        expectPrimaryFpr = false;
                    }
                }
                case "uid" -> {
                    if (current != null) {
                        current.userIds.add(unescape(field(f, 9)));
                    }
                }
                case "sub", "ssb" -> expectPrimaryFpr = false;
                default -> { }
            }
        }
        if (current != null) {
            keys.add(current.build());
        }
        return keys;
    }

    private static String field(String[] f, int i) {
        return i < f.length ? f[i] : "";
    }

    private static int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Instant epoch(String s) {
        if (s.isEmpty()) {
            return null;
        }
        if (s.contains("T")) {
            return null; // ISO form is only used with --fixed-list-mode off; treat as unknown
        }
        try {
            return Instant.ofEpochSecond(Long.parseLong(s));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static String algorithmName(String id, String curve) {
        return switch (id) {
            case "1", "2", "3" -> "RSA";
            case "16" -> "ElGamal";
            case "17" -> "DSA";
            case "18" -> "ECDH" + (curve.isEmpty() ? "" : " " + curve);
            case "19" -> "ECDSA" + (curve.isEmpty() ? "" : " " + curve);
            case "22" -> "EdDSA" + (curve.isEmpty() ? "" : " " + curve);
            default -> "algo " + id;
        };
    }

    /** User IDs escape ':' and other bytes as backslash-xHH. */
    static String unescape(String s) {
        StringBuilder out = new StringBuilder();
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 3 < s.length() && s.charAt(i + 1) == 'x') {
                bytes.write(Integer.parseInt(s.substring(i + 2, i + 4), 16));
                i += 3;
            } else {
                if (bytes.size() > 0) {
                    out.append(bytes.toString(java.nio.charset.StandardCharsets.UTF_8));
                    bytes.reset();
                }
                out.append(c);
            }
        }
        if (bytes.size() > 0) {
            out.append(bytes.toString(java.nio.charset.StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    private static final class Builder {
        boolean secret;
        String keyId = "";
        String fingerprint = "";
        String algorithm = "";
        int bits;
        Instant created;
        Instant expires;
        String validity = "";
        String capabilities = "";
        final List<String> userIds = new ArrayList<>();

        GpgKey build() {
            return new GpgKey(secret, keyId, fingerprint, algorithm, bits, created, expires, validity, capabilities,
                    List.copyOf(userIds));
        }
    }
}
