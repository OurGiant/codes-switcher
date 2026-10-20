package com.ourgiant.crypt;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Guesses what format a pasted string is in. Each guess has a score (0–100) and a short reason.
 * Guesses that map to a Text Codecs method carry that method name, so the UI can select it;
 * others (PEM, hashes, cipher output) only carry a hint about where to take the data.
 */
public final class FormatDetector {

    public record Guess(String method, String label, int score, String reason) {
        /** True when the guess maps to a Text Codecs method that can decode it. */
        public boolean decodable() {
            return method != null;
        }
    }

    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]+");
    private static final Pattern BINARY = Pattern.compile("[01]+");
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]+={0,2}");
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+={0,2}");
    private static final Pattern BASE32 = Pattern.compile("[A-Z2-7]+=*");
    private static final Pattern BASE58 = Pattern.compile("[1-9A-HJ-NP-Za-km-z]+");
    private static final Pattern JWT = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");
    private static final Pattern URL_ESCAPE = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern HTML_ENTITY = Pattern.compile("&(#x?[0-9a-fA-F]+|[a-zA-Z]+);");
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u(\\{[0-9a-fA-F]+}|[0-9a-fA-F]{4})");
    private static final Pattern JSON_ESCAPE = Pattern.compile("\\\\[\"\\\\/bfnrt]");
    private static final Pattern PEM = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");

    /** Guesses weaker than this are noise (e.g. a single word happens to use the Base64 alphabet). */
    static final int MIN_SCORE = 40;

    private FormatDetector() {
    }

    /** All plausible guesses, best first. Empty when nothing stands out (e.g. ordinary text). */
    public static List<Guess> detect(String input) {
        List<Guess> guesses = new ArrayList<>();
        if (input == null || input.isBlank()) {
            return guesses;
        }
        String s = input.strip();
        // Hex and binary are often grouped with spaces; Base-N text is only ever wrapped across lines.
        String compact = s.replaceAll("\\s+", "");
        String unwrapped = s.replaceAll("[\\r\\n]+", "");

        var pem = PEM.matcher(s);
        if (pem.find()) {
            guesses.add(new Guess(null, "PEM " + pem.group(1).toLowerCase(), 99,
                    "PEM block — open it in the JWT / X.509 Inspector"));
            return guesses;
        }

        if (JWT.matcher(compact).matches()) {
            String header = tryDecodeText(compact.substring(0, compact.indexOf('.')), true);
            if (header != null && header.contains("\"alg\"")) {
                guesses.add(new Guess(TextCodec.JWT, "JWT", 98, "Three Base64URL parts with an \"alg\" header"));
            }
        }

        if (compact.startsWith("<~") && compact.endsWith("~>")) {
            guesses.add(new Guess(TextCodec.ASCII85, "ASCII85", 95, "Wrapped in <~ ~>"));
        }

        if (compact.startsWith("H4sI") && BASE64.matcher(compact).matches()) {
            guesses.add(new Guess(TextCodec.GZIP, "Gzip (Base64)", 95, "Base64 of a gzip header (1f 8b)"));
        }

        if (compact.startsWith("Q1MB") && BASE64.matcher(compact).matches()) {
            guesses.add(new Guess(null, "AES / ChaCha20 output", 90,
                    "Starts with this app's encrypted-data header — use the AES / ChaCha20 tab"));
        }

        if (BINARY.matcher(compact).matches() && compact.length() % 8 == 0) {
            guesses.add(new Guess(TextCodec.BINARY, "Binary", 92, "Only 0s and 1s, in whole bytes"));
        }

        if (HEX.matcher(compact).matches() && compact.length() % 2 == 0) {
            String hash = hashName(compact.length());
            if (hash != null) {
                guesses.add(new Guess(null, hash + " hash?", 70,
                        compact.length() + " hex digits is the length of a " + hash + " digest (hashes can't be decoded)"));
            }
            boolean text = printable(hexBytes(compact));
            guesses.add(new Guess(TextCodec.HEX, "Hexadecimal", text ? 88 : 60,
                    text ? "Hex digits that decode to readable text" : "Hex digits (decodes to binary data)"));
            if (compact.length() % 16 == 0 && compact.equals(compact.toUpperCase()) && !text) {
                guesses.add(new Guess(null, "Blowfish (legacy) output?", 45,
                        "Upper-case hex in 8-byte blocks — try the Blowfish tab"));
            }
        }

        if (UNICODE_ESCAPE.matcher(s).find()) {
            guesses.add(new Guess(TextCodec.UNICODE, "Unicode escapes", 85, "Contains \\uXXXX sequences"));
        }

        if (URL_ESCAPE.matcher(s).find()) {
            guesses.add(new Guess(TextCodec.URL, "URL encoding", 82, "Contains %XX escapes"));
        } else if (s.contains("+") && !s.contains(" ") && s.contains("=") && s.contains("&")) {
            guesses.add(new Guess(TextCodec.URL, "URL encoding", 50, "Looks like a form-encoded query string"));
        }

        if (HTML_ENTITY.matcher(s).find()) {
            guesses.add(new Guess(TextCodec.HTML, "HTML entities", 82, "Contains &name; or &#x..; entities"));
        }

        if (JSON_ESCAPE.matcher(s).find() && !UNICODE_ESCAPE.matcher(s).find()) {
            guesses.add(new Guess(TextCodec.JSON, "JSON escape", 55, "Contains \\n, \\\" or similar escapes"));
        }

        if (unwrapped.length() >= 8 && unwrapped.length() % 8 == 0 && BASE32.matcher(unwrapped).matches()) {
            String text = tryBase32(unwrapped);
            guesses.add(new Guess(TextCodec.BASE32, "Base32", text != null ? 80 : 40,
                    text != null ? "Base32 alphabet that decodes to readable text" : "Base32 alphabet"));
        }

        boolean std = BASE64.matcher(unwrapped).matches();
        boolean url = !std && BASE64URL.matcher(unwrapped).matches();
        if ((std || url) && unwrapped.length() >= 4 && !BINARY.matcher(unwrapped).matches()) {
            String text = tryDecodeText(unwrapped, url);
            boolean padded = unwrapped.length() % 4 == 0;
            int score = text != null ? (padded ? 84 : 72) : (looksRandom(unwrapped) ? (padded ? 50 : 42) : 0);
            if (HEX.matcher(unwrapped).matches()) {
                score -= 30; // all-hex strings are usually hex, not Base64
            }
            guesses.add(new Guess(TextCodec.BASE64, url ? "Base64URL" : "Base64", score,
                    (text != null ? "Decodes to readable text" : "Base64 alphabet") + (url ? " (URL-safe alphabet)" : "")));
        }

        if (unwrapped.length() >= 6 && BASE58.matcher(unwrapped).matches() && !HEX.matcher(unwrapped).matches()) {
            String text = tryBase58(unwrapped);
            if (text != null) {
                guesses.add(new Guess(TextCodec.BASE58, "Base58", 55, "Base58 alphabet that decodes to readable text"));
            }
        }

        guesses.removeIf(g -> g.score() < MIN_SCORE);
        guesses.sort(Comparator.comparingInt(Guess::score).reversed());
        return guesses;
    }

    /** Base64 of binary data (keys, ciphertext) is long, mixed-case and has digits or symbols; words are not. */
    private static boolean looksRandom(String s) {
        return s.length() >= 16
                && s.chars().anyMatch(Character::isUpperCase)
                && s.chars().anyMatch(Character::isLowerCase)
                && s.chars().anyMatch(c -> Character.isDigit(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_');
    }

    /** The best guess that maps to a Text Codecs method, if any. */
    public static Guess bestDecodable(String input) {
        return detect(input).stream().filter(Guess::decodable).findFirst().orElse(null);
    }

    private static String hashName(int hexLength) {
        return switch (hexLength) {
            case 32 -> "MD5";
            case 40 -> "SHA-1";
            case 64 -> "SHA-256 / SHA3-256";
            case 128 -> "SHA-512 / SHA3-512 / BLAKE2b";
            default -> null;
        };
    }

    private static byte[] hexBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String tryDecodeText(String b64, boolean urlSafe) {
        try {
            String t = b64.replace("=", "");
            byte[] bytes = (urlSafe || t.contains("-") || t.contains("_") ? Base64.getUrlDecoder() : Base64.getDecoder())
                    .decode(t.length() % 4 == 1 ? t.substring(0, t.length() - 1) : t);
            return printable(bytes) ? new String(bytes, StandardCharsets.UTF_8) : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String tryBase32(String s) {
        try {
            byte[] b = ExtraCodecs.base32Decode(s);
            return printable(b) ? new String(b, StandardCharsets.UTF_8) : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String tryBase58(String s) {
        try {
            byte[] b = ExtraCodecs.base58Decode(s);
            return printable(b) ? new String(b, StandardCharsets.UTF_8) : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Valid UTF-8 with no control characters other than tab/newline/CR. */
    static boolean printable(byte[] bytes) {
        if (bytes.length == 0) {
            return false;
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return false;
        }
        return text.codePoints().allMatch(c -> c == '\n' || c == '\r' || c == '\t' || !Character.isISOControl(c));
    }
}
