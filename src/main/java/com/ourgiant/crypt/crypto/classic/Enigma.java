package com.ourgiant.crypt.crypto.classic;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * An Enigma I / M3 simulator: three rotors from I–VIII, reflector B or C, ring settings, start
 * positions and a plugboard, with the double-stepping of the middle rotor. Encrypting and
 * decrypting are the same operation from the same settings.
 */
public final class Enigma {

    /** The eight Wehrmacht/Kriegsmarine rotors and their turnover notches (as window letters). */
    public enum Rotor {
        I("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
        II("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
        III("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
        IV("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
        V("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
        VI("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
        VII("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
        VIII("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM");

        private final int[] forward = new int[26];
        private final int[] backward = new int[26];
        private final String notches;

        Rotor(String wiring, String notches) {
            for (int i = 0; i < 26; i++) {
                forward[i] = wiring.charAt(i) - 'A';
                backward[wiring.charAt(i) - 'A'] = i;
            }
            this.notches = notches;
        }

        public String notches() {
            return notches;
        }

        boolean atNotch(int position) {
            return notches.indexOf('A' + position) >= 0;
        }
    }

    public enum Reflector {
        B("YRUHQSLDPXNGOKMIEBFZCWVJAT"),
        C("FVPJIAOYEDRZXWGCTKUQSBNMHL");

        private final int[] wiring = new int[26];

        Reflector(String w) {
            for (int i = 0; i < 26; i++) {
                wiring[i] = w.charAt(i) - 'A';
            }
        }
    }

    private final Rotor[] rotors;
    private final Reflector reflector;
    private final int[] rings;
    private final int[] positions;
    private final int[] plugs = new int[26];

    /**
     * @param rotors    left, middle, right
     * @param rings     ring settings 1–26 (1 = A), left to right
     * @param start     window letters, left to right, e.g. "AAA"
     * @param plugboard letter pairs such as "AV BS CG", up to 13; blank for none
     */
    public Enigma(List<Rotor> rotors, Reflector reflector, int[] rings, String start, String plugboard) {
        if (rotors.size() != 3) {
            throw new IllegalArgumentException("Choose three rotors.");
        }
        if (rotors.stream().distinct().count() != 3) {
            throw new IllegalArgumentException("Each rotor can only be used once.");
        }
        if (rings.length != 3) {
            throw new IllegalArgumentException("Give three ring settings.");
        }
        this.rotors = rotors.toArray(new Rotor[0]);
        this.reflector = reflector;
        this.rings = new int[3];
        for (int i = 0; i < 3; i++) {
            if (rings[i] < 1 || rings[i] > 26) {
                throw new IllegalArgumentException("Ring settings go from 01 to 26 (A to Z).");
            }
            this.rings[i] = rings[i] - 1;
        }
        this.positions = parseStart(start);
        for (int i = 0; i < 26; i++) {
            plugs[i] = i;
        }
        for (String pair : parsePlugboard(plugboard)) {
            int a = pair.charAt(0) - 'A';
            int b = pair.charAt(1) - 'A';
            plugs[a] = b;
            plugs[b] = a;
        }
    }

    /** Current window letters, left to right. */
    public String positions() {
        char[] c = new char[3];
        for (int i = 0; i < 3; i++) {
            c[i] = (char) ('A' + positions[i]);
        }
        return new String(c);
    }

    /** Presses one key: steps the rotors, then sends {@code letter} (A–Z, either case) through. */
    public char press(char letter) {
        int c = Character.toUpperCase(letter) - 'A';
        if (c < 0 || c > 25) {
            throw new IllegalArgumentException("Not a letter: " + letter);
        }
        step();
        c = plugs[c];
        for (int i = 2; i >= 0; i--) {
            c = through(rotors[i].forward, i, c);
        }
        c = reflector.wiring[c];
        for (int i = 0; i < 3; i++) {
            c = through(rotors[i].backward, i, c);
        }
        return (char) ('A' + plugs[c]);
    }

    /**
     * Runs text through the machine. Letters come out in capitals. Non-letters are copied through
     * when {@code keepOther} is set and dropped otherwise; {@code groupOfFive} drops them and
     * groups the output in fives.
     */
    public String process(String text, boolean keepOther, boolean groupOfFive) {
        StringBuilder out = new StringBuilder();
        int letters = 0;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (isAsciiLetter(ch)) {
                if (groupOfFive && letters > 0 && letters % 5 == 0) {
                    out.append(' ');
                }
                out.append(press(ch));
                letters++;
            } else if (keepOther && !groupOfFive) {
                out.append(ch);
            }
        }
        return out.toString();
    }

    private void step() {
        // The middle rotor steps itself (and the left one) when it sits at its notch: the double step.
        if (rotors[1].atNotch(positions[1])) {
            positions[0] = (positions[0] + 1) % 26;
            positions[1] = (positions[1] + 1) % 26;
        } else if (rotors[2].atNotch(positions[2])) {
            positions[1] = (positions[1] + 1) % 26;
        }
        positions[2] = (positions[2] + 1) % 26;
    }

    private int through(int[] wiring, int slot, int c) {
        int shift = positions[slot] - rings[slot];
        return Math.floorMod(wiring[Math.floorMod(c + shift, 26)] - shift, 26);
    }

    private static boolean isAsciiLetter(char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
    }

    private static int[] parseStart(String start) {
        String s = start == null ? "" : start.replaceAll("[\\s,]", "").toUpperCase(Locale.ROOT);
        if (!s.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("Start positions are three letters, e.g. AAA.");
        }
        return new int[]{s.charAt(0) - 'A', s.charAt(1) - 'A', s.charAt(2) - 'A'};
    }

    /** Reads ring settings written as numbers ("01 21 12") or letters ("BUL", "B U L"). */
    public static int[] parseRings(String text) {
        String s = text == null ? "" : text.strip().toUpperCase(Locale.ROOT);
        if (s.matches("[A-Z]{3}")) {
            return new int[]{s.charAt(0) - 'A' + 1, s.charAt(1) - 'A' + 1, s.charAt(2) - 'A' + 1};
        }
        String[] parts = s.split("[\\s,\\-]+");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Ring settings are three numbers (01 01 01) or letters (AAA).");
        }
        int[] rings = new int[3];
        for (int i = 0; i < 3; i++) {
            if (parts[i].matches("[A-Z]")) {
                rings[i] = parts[i].charAt(0) - 'A' + 1;
            } else if (parts[i].matches("\\d{1,2}")) {
                rings[i] = Integer.parseInt(parts[i]);
            } else {
                throw new IllegalArgumentException("Can't read ring setting \"" + parts[i] + "\".");
            }
            if (rings[i] < 1 || rings[i] > 26) {
                throw new IllegalArgumentException("Ring settings go from 01 to 26 (A to Z).");
            }
        }
        return rings;
    }

    /** Checks and normalises plugboard pairs: "av bs" → [AV, BS]. Each letter at most once, at most 13 pairs. */
    public static List<String> parsePlugboard(String text) {
        String s = text == null ? "" : text.strip().toUpperCase(Locale.ROOT);
        if (s.isEmpty()) {
            return List.of();
        }
        String[] pairs = s.split("[\\s,;]+");
        if (pairs.length > 13) {
            throw new IllegalArgumentException("The plugboard takes at most 13 pairs.");
        }
        boolean[] used = new boolean[26];
        for (String p : pairs) {
            if (!p.matches("[A-Z]{2}")) {
                throw new IllegalArgumentException("Plugboard pairs are two letters, e.g. AV BS; can't read \"" + p + "\".");
            }
            for (char ch : p.toCharArray()) {
                if (used[ch - 'A']) {
                    throw new IllegalArgumentException("Plugboard letter " + ch + " is used more than once.");
                }
                used[ch - 'A'] = true;
            }
        }
        return Arrays.asList(pairs);
    }
}
