package com.ourgiant.crypt.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.function.LongConsumer;

/** Streams a file through a hash so large files don't need to fit in memory. */
public final class FileHasher {

    public enum Algorithm {
        SHA256("SHA-256", 64), SHA512("SHA-512", 128), SHA3_256("SHA3-256", 64), SHA3_512("SHA3-512", 128),
        BLAKE2B("BLAKE2b-512", 128), SHA1("SHA-1 (legacy)", 40), MD5("MD5 (legacy)", 32);

        private final String label;
        private final int hexLength;

        Algorithm(String label, int hexLength) {
            this.label = label;
            this.hexLength = hexLength;
        }

        public int hexLength() {
            return hexLength;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private FileHasher() {
    }

    /** Hashes a file, reporting bytes read so far to {@code progress} (may be null). */
    public static String hash(Path file, Algorithm algorithm, LongConsumer progress) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return hash(in, algorithm, progress);
        }
    }

    public static String hash(InputStream in, Algorithm algorithm, LongConsumer progress) throws IOException {
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        int n;
        if (algorithm == Algorithm.BLAKE2B) {
            Blake2b b = new Blake2b(64);
            while ((n = in.read(buf)) > 0) {
                b.update(buf, 0, n);
                total += n;
                report(progress, total);
            }
            return HexFormat.of().formatHex(b.digest());
        }
        MessageDigest md = digest(algorithm);
        while ((n = in.read(buf)) > 0) {
            md.update(buf, 0, n);
            total += n;
            report(progress, total);
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private static void report(LongConsumer progress, long total) {
        if (progress != null) {
            progress.accept(total);
            if (Thread.currentThread().isInterrupted()) {
                throw new java.util.concurrent.CancellationException("Hashing cancelled");
            }
        }
    }

    private static MessageDigest digest(Algorithm a) {
        String jca = switch (a) {
            case SHA256 -> "SHA-256";
            case SHA512 -> "SHA-512";
            case SHA3_256 -> "SHA3-256";
            case SHA3_512 -> "SHA3-512";
            case SHA1 -> "SHA-1";
            case MD5 -> "MD5";
            case BLAKE2B -> throw new IllegalStateException("BLAKE2b is not a JCA digest");
        };
        try {
            return MessageDigest.getInstance(jca);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(jca + " unavailable", e);
        }
    }

    /**
     * Normalises an expected hash as people paste it: trims, lower-cases, removes spaces and colons,
     * and accepts {@code sha256sum}-style lines ("hash  filename") or "SHA256 (file) = hash".
     */
    public static String normalizeExpected(String expected) {
        if (expected == null) {
            return "";
        }
        String s = expected.strip();
        int eq = s.lastIndexOf('=');
        if (eq >= 0 && s.contains("(")) {
            s = s.substring(eq + 1).strip(); // BSD style: SHA256 (file) = abc...
        } else if (s.matches("(?s)[0-9a-fA-F]{32,}\\s+\\*?\\S.*")) {
            s = s.split("\\s+", 2)[0]; // GNU style: abc...  file
        }
        return s.replaceAll("[\\s:]", "").toLowerCase(Locale.ROOT);
    }

    /** True when the expected hash (in any of the pasted forms above) equals {@code actualHex}. */
    public static boolean matches(String expected, String actualHex) {
        String e = normalizeExpected(expected);
        return !e.isEmpty() && MessageDigest.isEqual(e.getBytes(), actualHex.toLowerCase(Locale.ROOT).getBytes());
    }

    /** Algorithms whose digest length matches the expected hash, to suggest one. */
    public static java.util.List<Algorithm> candidatesFor(String expected) {
        int len = normalizeExpected(expected).length();
        return java.util.Arrays.stream(Algorithm.values()).filter(a -> a.hexLength == len).toList();
    }
}
