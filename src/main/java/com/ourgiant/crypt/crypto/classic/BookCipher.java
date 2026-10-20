package com.ourgiant.crypt.crypto.classic;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.random.RandomGenerator;

/**
 * A book (Ottendorf) cipher. The book is any text: lines and words are counted from 1. In word
 * mode each word becomes "line-word"; in letter mode each letter becomes "line-word-letter" and
 * a space between words becomes "/". Encoding picks a random place each time, so a repeated word
 * doesn't repeat its code. Matching ignores case and punctuation around the book's words.
 */
public final class BookCipher {

    public enum Mode { WORD, LETTER }

    private record Spot(int line, int word) {
    }

    private record LetterSpot(int line, int word, int letter) {
    }

    /** lines.get(l).get(w) = the cleaned, lower-case word; "" for a word that's only punctuation. */
    private final List<List<String>> lines = new ArrayList<>();
    private final Map<String, List<Spot>> wordSpots = new HashMap<>();
    private final Map<Character, List<LetterSpot>> letterSpots = new HashMap<>();
    private final RandomGenerator random;

    public BookCipher(String book, RandomGenerator random) {
        this.random = random;
        String[] raw = (book == null ? "" : book).split("\\R", -1);
        for (int l = 0; l < raw.length; l++) {
            List<String> words = new ArrayList<>();
            String line = raw[l].strip();
            if (!line.isEmpty()) {
                for (String w : line.split("\\s+")) {
                    words.add(clean(w));
                }
            }
            lines.add(words);
            for (int w = 0; w < words.size(); w++) {
                String word = words.get(w);
                if (word.isEmpty()) {
                    continue;
                }
                wordSpots.computeIfAbsent(word, k -> new ArrayList<>()).add(new Spot(l + 1, w + 1));
                for (int i = 0; i < word.length(); i++) {
                    letterSpots.computeIfAbsent(word.charAt(i), k -> new ArrayList<>()).add(new LetterSpot(l + 1, w + 1, i + 1));
                }
            }
        }
        if (wordSpots.isEmpty()) {
            throw new IllegalArgumentException("The book is empty: paste or load some text to use as the key.");
        }
    }

    public int lineCount() {
        return lines.size();
    }

    public int wordCount() {
        return lines.stream().mapToInt(List::size).sum();
    }

    public String encode(String plaintext, Mode mode) {
        return mode == Mode.WORD ? encodeWords(plaintext) : encodeLetters(plaintext);
    }

    private String encodeWords(String plaintext) {
        List<String> codes = new ArrayList<>();
        for (String w : words(plaintext)) {
            List<Spot> spots = wordSpots.get(w);
            if (spots == null) {
                throw new IllegalArgumentException("The word \"" + w + "\" isn't in the book.");
            }
            Spot s = spots.get(random.nextInt(spots.size()));
            codes.add(s.line() + "-" + s.word());
        }
        if (codes.isEmpty()) {
            throw new IllegalArgumentException("Nothing to encode: type some words.");
        }
        return String.join(" ", codes);
    }

    private String encodeLetters(String plaintext) {
        List<String> codes = new ArrayList<>();
        for (String w : words(plaintext)) {
            if (!codes.isEmpty()) {
                codes.add("/");
            }
            for (int i = 0; i < w.length(); i++) {
                char ch = w.charAt(i);
                if (!Character.isLetterOrDigit(ch)) {
                    continue;
                }
                List<LetterSpot> spots = letterSpots.get(ch);
                if (spots == null) {
                    throw new IllegalArgumentException("The letter \"" + ch + "\" isn't anywhere in the book.");
                }
                LetterSpot s = spots.get(random.nextInt(spots.size()));
                codes.add(s.line() + "-" + s.word() + "-" + s.letter());
            }
        }
        if (codes.isEmpty()) {
            throw new IllegalArgumentException("Nothing to encode: type some letters.");
        }
        return String.join(" ", codes);
    }

    /**
     * Decodes codes separated by spaces or commas. "line-word" gives a word, "line-word-letter" a
     * letter, and "/" a space; '.', ':' or '/' inside a code work as well as '-'.
     */
    public String decode(String codes) {
        StringBuilder out = new StringBuilder();
        boolean lastWasWord = false;
        for (String token : (codes == null ? "" : codes).strip().split("[\\s,;]+")) {
            if (token.isEmpty()) {
                continue;
            }
            if (token.equals("/") || token.equals("|")) {
                out.append(' ');
                lastWasWord = false;
                continue;
            }
            String[] parts = token.split("[-.:/]");
            if (parts.length < 2 || parts.length > 3 || !token.matches("\\d+([-.:/]\\d+){1,2}")) {
                throw new IllegalArgumentException("Can't read code \"" + token + "\": use line-word or line-word-letter.");
            }
            int line = number(parts[0], token);
            int word = number(parts[1], token);
            if (line < 1 || line > lines.size()) {
                throw new IllegalArgumentException("Code " + token + " is out of range: the book has "
                        + lines.size() + " line" + (lines.size() == 1 ? "" : "s") + ".");
            }
            List<String> ws = lines.get(line - 1);
            if (word < 1 || word > ws.size()) {
                throw new IllegalArgumentException("Code " + token + " is out of range: line " + line + " has "
                        + ws.size() + " word" + (ws.size() == 1 ? "" : "s") + ".");
            }
            String w = ws.get(word - 1);
            if (parts.length == 2) {
                if (lastWasWord) {
                    out.append(' ');
                }
                out.append(w);
                lastWasWord = true;
            } else {
                int letter = number(parts[2], token);
                if (letter < 1 || letter > w.length()) {
                    throw new IllegalArgumentException("Code " + token + " is out of range: word " + word + " on line "
                            + line + " (\"" + w + "\") has " + w.length() + " letter" + (w.length() == 1 ? "" : "s") + ".");
                }
                if (lastWasWord) {
                    out.append(' ');
                }
                out.append(w.charAt(letter - 1));
                lastWasWord = false;
            }
        }
        return out.toString();
    }

    private static int number(String s, String token) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Code " + token + " is out of range.");
        }
    }

    private static List<String> words(String text) {
        List<String> out = new ArrayList<>();
        for (String w : (text == null ? "" : text).strip().split("\\s+")) {
            String c = clean(w);
            if (!c.isEmpty()) {
                out.add(c);
            }
        }
        return out;
    }

    /** Lower-cases and strips punctuation from both ends: "\"Freedom!\"" → "freedom". */
    static String clean(String word) {
        int start = 0;
        int end = word.length();
        while (start < end && !Character.isLetterOrDigit(word.charAt(start))) {
            start++;
        }
        while (end > start && !Character.isLetterOrDigit(word.charAt(end - 1))) {
            end--;
        }
        return word.substring(start, end).toLowerCase(Locale.ROOT);
    }
}
