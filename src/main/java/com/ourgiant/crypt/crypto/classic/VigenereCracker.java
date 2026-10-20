package com.ourgiant.crypt.crypto.classic;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Breaks a Vigenère ciphertext without the key. Key lengths are ranked by the average index of
 * coincidence of their columns (with Kasiski repeat distances shown alongside); for the best
 * lengths each column's shift is the one whose letters best fit English (chi-square), and the
 * resulting keys are ranked by how English the whole decryption is.
 */
public final class VigenereCracker {

    /** Columns shorter than this give too little to go on, so longer keys aren't tried. */
    static final int MIN_COLUMN = 6;
    /** How many of the best-scoring key lengths get a key recovered. */
    static final int LENGTHS_TRIED = 8;
    /** A key length is skipped when a divisor of it has at least this share of its IoC. */
    static final double MULTIPLE_RATIO = 0.95;

    /** One key length: average column IoC (English ≈ 0.066, random ≈ 0.038) and Kasiski votes. */
    public record KeyLength(int length, double ioc, int kasiski) {
    }

    /** A recovered key and the text it gives; lower score is more English-like. */
    public record Candidate(String key, double score, String plaintext) {
    }

    public record Result(int letters, List<KeyLength> lengths, List<Candidate> candidates) {
    }

    private VigenereCracker() {
    }

    /** Needs a few hundred letters to be reliable; tries keys up to {@code maxKeyLength} letters. */
    public static Result crack(String ciphertext, int maxKeyLength, int topCandidates) {
        int[] letters = letters(ciphertext);
        if (letters.length < 2 * MIN_COLUMN) {
            throw new IllegalArgumentException("Need more ciphertext: at least " + 2 * MIN_COLUMN
                    + " letters, and a few hundred to crack it reliably.");
        }
        int max = Math.max(1, Math.min(maxKeyLength, letters.length / MIN_COLUMN));
        int[] kasiski = kasiski(letters, max);
        List<KeyLength> lengths = new ArrayList<>();
        for (int len = 1; len <= max; len++) {
            lengths.add(new KeyLength(len, averageIoc(letters, len), kasiski[len]));
        }

        List<KeyLength> best = new ArrayList<>(lengths);
        best.sort(Comparator.comparingDouble(KeyLength::ioc).reversed());
        List<KeyLength> tried = best.subList(0, Math.min(LENGTHS_TRIED, best.size()));
        Map<String, Candidate> byKey = new LinkedHashMap<>();
        for (KeyLength kl : tried) {
            // A multiple of a length that scores about as well only adds noise (its columns overfit).
            if (tried.stream().anyMatch(p -> p.length() < kl.length() && kl.length() % p.length() == 0
                    && p.ioc() >= MULTIPLE_RATIO * kl.ioc())) {
                continue;
            }
            String key = shortestPeriod(recoverKey(letters, kl.length()));
            if (!byKey.containsKey(key)) {
                String plain = ClassicCiphers.vigenereDecrypt(ciphertext, key);
                byKey.put(key, new Candidate(key, ClassicCiphers.englishScore(plain), plain));
            }
        }
        List<Candidate> candidates = new ArrayList<>(byKey.values());
        candidates.sort(Comparator.comparingDouble(Candidate::score).thenComparingInt(c -> c.key().length()));
        return new Result(letters.length, lengths, candidates.subList(0, Math.min(topCandidates, candidates.size())));
    }

    /** Best key of exactly {@code length} letters, one chi-square fit per column. */
    static String recoverKey(int[] letters, int length) {
        StringBuilder key = new StringBuilder();
        for (int col = 0; col < length; col++) {
            int[] counts = new int[26];
            int n = 0;
            for (int i = col; i < letters.length; i += length) {
                counts[letters[i]]++;
                n++;
            }
            int bestShift = 0;
            double bestChi = Double.MAX_VALUE;
            for (int s = 0; s < 26; s++) {
                int[] shifted = new int[26];
                for (int c = 0; c < 26; c++) {
                    shifted[c] = counts[(c + s) % 26];
                }
                double chi = ClassicCiphers.chiSquare(shifted, n);
                if (chi < bestChi) {
                    bestChi = chi;
                    bestShift = s;
                }
            }
            key.append((char) ('A' + bestShift));
        }
        return key.toString();
    }

    /** "LEMONLEMON" → "LEMON". */
    static String shortestPeriod(String key) {
        for (int p = 1; p < key.length(); p++) {
            if (key.length() % p == 0 && key.equals(key.substring(0, p).repeat(key.length() / p))) {
                return key.substring(0, p);
            }
        }
        return key;
    }

    static double averageIoc(int[] letters, int length) {
        double sum = 0;
        for (int col = 0; col < length; col++) {
            int[] counts = new int[26];
            int n = 0;
            for (int i = col; i < letters.length; i += length) {
                counts[letters[i]]++;
                n++;
            }
            if (n > 1) {
                long pairs = 0;
                for (int c : counts) {
                    pairs += (long) c * (c - 1);
                }
                sum += pairs / (double) (n * (n - 1));
            }
        }
        return sum / length;
    }

    /** For each length 2..max, how many distances between repeated trigrams it divides. */
    static int[] kasiski(int[] letters, int max) {
        int[] votes = new int[max + 1];
        Map<Integer, Integer> last = new HashMap<>();
        for (int i = 0; i + 3 <= letters.length; i++) {
            int tri = letters[i] * 676 + letters[i + 1] * 26 + letters[i + 2];
            Integer prev = last.put(tri, i);
            if (prev != null) {
                int distance = i - prev;
                for (int len = 2; len <= max; len++) {
                    if (distance % len == 0) {
                        votes[len]++;
                    }
                }
            }
        }
        return votes;
    }

    private static int[] letters(String text) {
        int[] out = new int[text.length()];
        int n = 0;
        for (int i = 0; i < text.length(); i++) {
            int base = ClassicCiphers.base(text.charAt(i));
            if (base != 0) {
                out[n++] = text.charAt(i) - base;
            }
        }
        return java.util.Arrays.copyOf(out, n);
    }
}
