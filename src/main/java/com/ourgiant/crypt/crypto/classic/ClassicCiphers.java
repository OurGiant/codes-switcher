package com.ourgiant.crypt.crypto.classic;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Atbash, Caesar and Vigenère over the 26 Latin letters, plus a simple "how English is this"
 * score. Case and anything that isn't A–Z are kept in place.
 */
public final class ClassicCiphers {

    /** English letter frequencies, A–Z, as fractions. */
    static final double[] ENGLISH = {
            0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
            0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
            0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

    /** One Caesar shift tried by {@link #caesarAll}: lower score is more English-like. */
    public record CaesarCandidate(int shift, String text, double score) {
    }

    private ClassicCiphers() {
    }

    /** A↔Z, B↔Y, … Its own inverse. */
    public static String atbash(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            int base = base(ch);
            out.append(base == 0 ? ch : (char) (base + 25 - (ch - base)));
        }
        return out.toString();
    }

    /** Shifts each letter forward by {@code shift} (any integer; negative shifts back). */
    public static String caesar(String text, int shift) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            out.append(shift(text.charAt(i), shift));
        }
        return out.toString();
    }

    /** All 26 Caesar decryptions (shift = how far the ciphertext was shifted), most English-like first. */
    public static List<CaesarCandidate> caesarAll(String ciphertext) {
        List<CaesarCandidate> all = new ArrayList<>();
        for (int s = 0; s < 26; s++) {
            String plain = caesar(ciphertext, -s);
            all.add(new CaesarCandidate(s, plain, englishScore(plain)));
        }
        all.sort(Comparator.comparingDouble(CaesarCandidate::score).thenComparingInt(CaesarCandidate::shift));
        return all;
    }

    public static String vigenereEncrypt(String text, String key) {
        return vigenere(text, key, 1);
    }

    public static String vigenereDecrypt(String text, String key) {
        return vigenere(text, key, -1);
    }

    /** The key's letters as shifts 0–25; other characters in the key are ignored. */
    static int[] keyShifts(String key) {
        String k = key == null ? "" : key.toUpperCase(Locale.ROOT).replaceAll("[^A-Z]", "");
        if (k.isEmpty()) {
            throw new IllegalArgumentException("The keyword needs at least one letter A–Z.");
        }
        int[] shifts = new int[k.length()];
        for (int i = 0; i < k.length(); i++) {
            shifts[i] = k.charAt(i) - 'A';
        }
        return shifts;
    }

    private static String vigenere(String text, String key, int direction) {
        int[] shifts = keyShifts(key);
        StringBuilder out = new StringBuilder(text.length());
        int j = 0;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (base(ch) == 0) {
                out.append(ch); // non-letters don't use up a key letter
            } else {
                out.append(shift(ch, direction * shifts[j++ % shifts.length]));
            }
        }
        return out.toString();
    }

    /**
     * Chi-square distance of the text's letter counts from English: lower means more English-like.
     * Text with no letters scores {@link Double#MAX_VALUE}.
     */
    public static double englishScore(String text) {
        int[] counts = new int[26];
        int n = 0;
        for (int i = 0; i < text.length(); i++) {
            int base = base(text.charAt(i));
            if (base != 0) {
                counts[text.charAt(i) - base]++;
                n++;
            }
        }
        return n == 0 ? Double.MAX_VALUE : chiSquare(counts, n);
    }

    static double chiSquare(int[] counts, int n) {
        double chi = 0;
        for (int i = 0; i < 26; i++) {
            double expected = ENGLISH[i] * n;
            double d = counts[i] - expected;
            chi += d * d / expected;
        }
        return chi;
    }

    /** 'A' or 'a' for an ASCII letter, else 0. */
    static int base(char ch) {
        if (ch >= 'A' && ch <= 'Z') {
            return 'A';
        }
        return ch >= 'a' && ch <= 'z' ? 'a' : 0;
    }

    private static char shift(char ch, int by) {
        int base = base(ch);
        return base == 0 ? ch : (char) (base + Math.floorMod(ch - base + by, 26));
    }
}
