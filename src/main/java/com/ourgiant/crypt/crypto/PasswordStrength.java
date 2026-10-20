package com.ourgiant.crypt.crypto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Estimates how many guesses a password would take, in the spirit of zxcvbn: the password is split
 * into the cheapest mix of known patterns (common passwords and words, with case and look-alike
 * swaps; repeats; sequences; keyboard runs; years) and plain brute-forced characters. The result is
 * a guess count, a rating, plain warnings and crack-time estimates for a few attack scenarios.
 *
 * <p>It's an estimate for a person choosing a password, not a guarantee: real attackers use far
 * bigger word lists. The password is only held in memory for the call.
 */
public final class PasswordStrength {

    public enum Rating {
        VERY_WEAK("Very weak"), WEAK("Weak"), FAIR("Fair"), STRONG("Strong"), VERY_STRONG("Very strong");

        private final String label;

        Rating(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** Average time to find the password at {@code guessesPerSecond}. */
    public record CrackTime(String scenario, double guessesPerSecond, double seconds) {
        public String display() {
            return formatDuration(seconds);
        }
    }

    public record Result(double bits, double guesses, Rating rating, List<String> warnings, List<CrackTime> crackTimes) {
    }

    /** Attack speeds, slowest first. */
    static final Object[][] SCENARIOS = {
            {"Online, rate-limited (100 guesses an hour)", 100.0 / 3600},
            {"Online, no rate limit (10 a second)", 10.0},
            {"Offline, slow hash like PBKDF2 600k (10,000 a second)", 1e4},
            {"Offline, fast hash like MD5 or SHA-1 (10 billion a second)", 1e10},
    };

    /** The attack scenarios' descriptions, in the order {@link Result#crackTimes()} lists them. */
    public static List<String> scenarioNames() {
        List<String> names = new ArrayList<>();
        for (Object[] s : SCENARIOS) {
            names.add((String) s[0]);
        }
        return names;
    }

    /** Some of the most-leaked passwords, most common first (rank = position + 1). */
    static final List<String> COMMON = List.of(
            "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777",
            "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
            "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
            "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "112233", "george", "computer",
            "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
            "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
            "love", "ashley", "nicole", "chelsea", "matthew", "access", "yankees", "987654321", "dallas", "austin",
            "thunder", "taylor", "matrix", "admin", "welcome", "login", "passw0rd", "password1", "qwerty123", "secret",
            "whatever", "hello", "flower", "lovely", "monkey1", "football1", "baseball1", "letmein1", "welcome1",
            "abcdef", "abcd1234", "1q2w3e4r", "qwe123", "zaq12wsx", "asdf", "asdfghjkl", "q1w2e3r4", "123abc",
            "swordfish", "god", "jesus", "angel", "liverpool", "arsenal", "banana", "orange", "purple", "silver",
            "diamond", "falcon", "eagle", "tiger", "dolphin", "phoenix", "samsung", "apple", "google", "internet",
            "cookie", "chocolate", "coffee", "pokemon", "minecraft", "naruto", "batman1", "superman1", "pa55word",
            "changeme", "default", "root", "toor", "guest", "test", "test123", "qwerty1", "abc", "xxx");

    /** Common English words that turn up in passwords. */
    static final List<String> WORDS = List.of(
            "the", "and", "you", "love", "baby", "life", "home", "family", "friend", "happy", "lucky", "magic",
            "money", "power", "sweet", "honey", "angel", "devil", "heaven", "hell", "star", "moon", "sun", "sky",
            "blue", "red", "green", "black", "white", "pink", "gold", "dark", "light", "fire", "water", "earth",
            "wind", "storm", "snow", "rain", "winter", "spring", "autumn", "fall", "night", "day", "time", "world",
            "king", "queen", "prince", "lady", "boy", "girl", "man", "woman", "dog", "cat", "bear", "wolf", "lion",
            "horse", "bird", "fish", "shark", "snake", "dragon", "tiger", "monkey", "rabbit", "mouse", "duck",
            "pizza", "beer", "wine", "candy", "sugar", "butter", "bread", "cake", "pie", "music", "rock", "metal",
            "dance", "party", "game", "games", "player", "soccer", "ball", "team", "club", "city", "house", "car",
            "summer", "secret", "hidden", "access", "admin", "login", "user", "pass", "word", "code", "codes",
            "hacker", "hack", "planet", "matrix", "neo", "zion", "cyber", "crypto", "cipher", "key", "lock",
            "open", "door", "garden", "flower", "rose", "lily", "daisy", "cherry", "apple", "lemon", "peach",
            "school", "work", "office", "phone", "mobile", "email", "computer", "laptop", "windows", "linux",
            "monday", "friday", "sunday", "january", "june", "july", "august", "october", "december",
            "correct", "horse", "battery", "staple", "troubador", "troubadour", "trouble", "freedom", "liberty", "justice",
            "victory");

    private static final String[] KEYBOARD_ROWS = {"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "1qaz2wsx3edc4rfv", "qazwsxedcrfv"};
    private static final int MAX_ANALYSED = 128;
    private static final Map<String, Integer> RANKS = new HashMap<>();

    static {
        for (int i = 0; i < COMMON.size(); i++) {
            RANKS.putIfAbsent(COMMON.get(i), i + 1);
        }
        for (int i = 0; i < WORDS.size(); i++) {
            RANKS.putIfAbsent(WORDS.get(i), COMMON.size() + i + 1);
        }
    }

    private PasswordStrength() {
    }

    private enum Kind { BRUTE, COMMON, WORD, REPEAT, SEQUENCE, KEYBOARD, YEAR }

    private record Token(int start, int end, double bits, Kind kind, String match, boolean leet) {
    }

    public static Result estimate(String password) {
        String pw = password.length() > MAX_ANALYSED ? password.substring(0, MAX_ANALYSED) : password;
        int n = pw.length();
        double perChar = log2(charsetSize(password));

        List<Token> tokens = new ArrayList<>();
        findDictionary(pw, tokens);
        findRepeats(pw, tokens);
        findSequences(pw, tokens);
        findKeyboard(pw, tokens);
        findYears(pw, tokens);

        // Cheapest split: best[i] = bits to guess pw[0, i).
        double[] best = new double[n + 1];
        Token[] via = new Token[n + 1];
        for (int i = 1; i <= n; i++) {
            best[i] = best[i - 1] + perChar;
            via[i] = new Token(i - 1, i, perChar, Kind.BRUTE, null, false);
            for (Token t : tokens) {
                // One extra bit per pattern, for the attacker not knowing how the pieces combine.
                double cost = best[t.start()] + t.bits() + (t.start() == 0 && t.end() == n ? 0 : 1);
                if (t.end() == i && cost < best[i]) {
                    best[i] = cost;
                    via[i] = t;
                }
            }
        }
        double bits = best[n] + (password.length() - n) * perChar;

        List<Token> path = new ArrayList<>();
        for (int i = n; i > 0; i = via[i].start()) {
            path.add(0, via[i]);
        }
        double guesses = Math.pow(2, bits);
        Rating rating = rate(bits, password.length());
        List<CrackTime> times = new ArrayList<>();
        for (Object[] s : SCENARIOS) {
            double rate = (Double) s[1];
            times.add(new CrackTime((String) s[0], rate, guesses / 2 / rate));
        }
        return new Result(bits, guesses, rating, warnings(password, path), times);
    }

    static Rating rate(double bits, int length) {
        Rating r = bits < 28 ? Rating.VERY_WEAK : bits < 36 ? Rating.WEAK : bits < 60 ? Rating.FAIR
                : bits < 80 ? Rating.STRONG : Rating.VERY_STRONG;
        return length < 8 && r.ordinal() > Rating.WEAK.ordinal() ? Rating.WEAK : r;
    }

    private static List<String> warnings(String password, List<Token> path) {
        Set<String> w = new LinkedHashSet<>();
        if (password.isEmpty()) {
            return List.of("Type a password to check it.");
        }
        for (Token t : path) {
            switch (t.kind()) {
                case COMMON -> w.add(path.size() == 1 ? "This is one of the most common passwords. It would be guessed almost at once."
                        : "Contains a very common password: \"" + t.match() + "\".");
                case WORD -> w.add("Contains a common word: \"" + t.match() + "\". Single words are early guesses.");
                case REPEAT -> w.add("Repeated characters like \"aaa\" add almost nothing.");
                case SEQUENCE -> w.add("Sequences like abc or 123 are easy to guess.");
                case KEYBOARD -> w.add("Keyboard patterns like qwerty or asdf are easy to guess.");
                case YEAR -> w.add("Years, like birth years, are easy to guess.");
                default -> { }
            }
            if (t.leet()) {
                w.add("Swapping letters for look-alikes (p@ssw0rd) barely helps: attackers try those too.");
            }
        }
        if (password.length() < 12) {
            w.add("Use at least 12 characters. Length helps more than symbols; a few random words work well.");
        }
        return List.copyOf(w);
    }

    // ------------------------------------------------------------------ pattern finders

    private static void findDictionary(String pw, List<Token> out) {
        int n = pw.length();
        for (int i = 0; i < n; i++) {
            for (int j = i + 3; j <= Math.min(n, i + 20); j++) {
                String sub = pw.substring(i, j);
                String lower = sub.toLowerCase(Locale.ROOT);
                for (String candidate : unleet(lower)) {
                    Integer rank = RANKS.get(candidate);
                    if (rank == null) {
                        continue;
                    }
                    boolean isWord = rank > COMMON.size();
                    if (isWord && candidate.length() < 3) {
                        continue;
                    }
                    boolean leet = !candidate.equals(lower);
                    double bits = log2(rank) + caseBits(sub) + (leet ? Math.max(1, leetCount(lower, candidate)) : 0);
                    out.add(new Token(i, j, bits, isWord ? Kind.WORD : Kind.COMMON, candidate, leet));
                }
            }
        }
    }

    /** The lowercase string with common look-alike swaps undone ('1' tried as both i and l). */
    static List<String> unleet(String lower) {
        StringBuilder a = new StringBuilder(lower.length());
        StringBuilder b = new StringBuilder(lower.length());
        for (char c : lower.toCharArray()) {
            char m = switch (c) {
                case '4', '@' -> 'a';
                case '3' -> 'e';
                case '1', '!', '|' -> 'i';
                case '0' -> 'o';
                case '5', '$' -> 's';
                case '7', '+' -> 't';
                case '8' -> 'b';
                default -> c;
            };
            a.append(m);
            b.append(c == '1' ? 'l' : m);
        }
        List<String> out = new ArrayList<>(List.of(lower));
        for (String s : List.of(a.toString(), b.toString())) {
            if (!out.contains(s)) {
                out.add(s);
            }
        }
        return out;
    }

    private static int leetCount(String lower, String candidate) {
        int k = 0;
        for (int i = 0; i < lower.length(); i++) {
            if (lower.charAt(i) != candidate.charAt(i)) {
                k++;
            }
        }
        return k;
    }

    /** Bits for the capitalisation: none for lower case, 1 for Capitalised or ALL CAPS, more for mixed. */
    static double caseBits(String s) {
        int upper = 0;
        int lower = 0;
        for (char c : s.toCharArray()) {
            if (Character.isUpperCase(c)) {
                upper++;
            } else if (Character.isLowerCase(c)) {
                lower++;
            }
        }
        if (upper == 0) {
            return 0;
        }
        if (lower == 0 || (upper == 1 && Character.isUpperCase(s.charAt(0)))) {
            return 1;
        }
        double ways = 0;
        for (int k = 1; k <= Math.min(upper, lower); k++) {
            ways += binomial(upper + lower, k);
        }
        return log2(ways);
    }

    private static void findRepeats(String pw, List<Token> out) {
        int n = pw.length();
        int i = 0;
        while (i < n) {
            int j = i + 1;
            while (j < n && pw.charAt(j) == pw.charAt(i)) {
                j++;
            }
            if (j - i >= 3) {
                out.add(new Token(i, j, log2(charsetSize(pw.substring(i, i + 1))) + log2(j - i), Kind.REPEAT, null, false));
            }
            i = j;
        }
    }

    private static void findSequences(String pw, List<Token> out) {
        int n = pw.length();
        int i = 0;
        while (i < n - 2) {
            int delta = pw.charAt(i + 1) - pw.charAt(i);
            if (Math.abs(delta) != 1 || !sameClass(pw.charAt(i), pw.charAt(i + 1))) {
                i++;
                continue;
            }
            int j = i + 2;
            while (j < n && pw.charAt(j) - pw.charAt(j - 1) == delta && sameClass(pw.charAt(j), pw.charAt(i))) {
                j++;
            }
            if (j - i >= 3) {
                double base = Character.isDigit(pw.charAt(i)) ? log2(10) : log2(26);
                out.add(new Token(i, j, base + log2(j - i) + (delta < 0 ? 1 : 0), Kind.SEQUENCE, null, false));
                i = j - 1;
            } else {
                i++;
            }
        }
    }

    private static void findKeyboard(String pw, List<Token> out) {
        String lower = pw.toLowerCase(Locale.ROOT);
        int n = lower.length();
        for (int i = 0; i < n; i++) {
            for (int j = i + 4; j <= n; j++) {
                String sub = lower.substring(i, j);
                String rev = new StringBuilder(sub).reverse().toString();
                for (String row : KEYBOARD_ROWS) {
                    boolean fwd = row.contains(sub);
                    if (fwd || row.contains(rev)) {
                        out.add(new Token(i, j, log2(40) + log2(j - i) + (fwd ? 0 : 1) + caseBits(pw.substring(i, j)),
                                Kind.KEYBOARD, null, false));
                        break;
                    }
                }
            }
        }
    }

    private static void findYears(String pw, List<Token> out) {
        for (int i = 0; i + 4 <= pw.length(); i++) {
            String sub = pw.substring(i, i + 4);
            if (sub.chars().allMatch(Character::isDigit)) {
                int y = Integer.parseInt(sub);
                if (y >= 1900 && y <= 2039) {
                    out.add(new Token(i, i + 4, log2(140), Kind.YEAR, null, false));
                }
            }
        }
    }

    private static boolean sameClass(char a, char b) {
        return (Character.isDigit(a) && Character.isDigit(b))
                || (Character.isLowerCase(a) && Character.isLowerCase(b))
                || (Character.isUpperCase(a) && Character.isUpperCase(b));
    }

    /** Size of the alphabet an attacker would brute-force, from the kinds of characters used. */
    static int charsetSize(String s) {
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        boolean other = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c >= 0x20 && c < 0x7f) {
                symbol = true;
            } else {
                other = true;
            }
        }
        int size = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0) + (other ? 100 : 0);
        return Math.max(size, 1);
    }

    /** "less than a second", "3 minutes", "about 5 years", "centuries". */
    public static String formatDuration(double seconds) {
        if (seconds < 1) {
            return "less than a second";
        }
        double[] limits = {60, 3600, 86400, 86400 * 30.44, 86400 * 365.25, 86400 * 365.25 * 100};
        String[] units = {"second", "minute", "hour", "day", "month", "year"};
        double[] sizes = {1, 60, 3600, 86400, 86400 * 30.44, 86400 * 365.25};
        for (int i = 0; i < limits.length; i++) {
            if (seconds < limits[i]) {
                long v = Math.round(seconds / sizes[i]);
                return (i >= 4 ? "about " : "") + v + " " + units[i] + (v == 1 ? "" : "s");
            }
        }
        return "centuries";
    }

    private static double binomial(int n, int k) {
        double r = 1;
        for (int i = 1; i <= k; i++) {
            r = r * (n - k + i) / i;
        }
        return r;
    }

    private static double log2(double x) {
        return Math.log(x) / Math.log(2);
    }
}
