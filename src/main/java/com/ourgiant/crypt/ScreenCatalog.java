package com.ourgiant.crypt;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Every screen the main window can show, how the sidebar groups them, and how a name typed in
 * the sidebar search or passed as {@code --tool=} finds one. Swing-free so it can be unit-tested.
 */
final class ScreenCatalog {

    /** Which tool class builds a screen. Each is created the first time one of its screens is opened. */
    enum Provider { CODECS, INSPECTOR, GPG, STEGO, HISTORY }

    /**
     * @param title    the tab title the screen has in its own window, used as its id
     * @param label    what the sidebar shows (shorter, since the group heading gives context)
     * @param aliases  extra words for search and {@code --tool=}
     */
    record Entry(String title, String group, String label, Provider provider, List<String> aliases) {
    }

    static final List<String> GROUPS = List.of("Encode / Decode", "Ciphers", "JWT", "Certificates", "GPG", "Steganography", "Session");

    static final List<Entry> ENTRIES = List.of(
            e("Text Codecs", "Encode / Decode", "Text Codecs", Provider.CODECS, "codecs", "encode", "decode", "base64", "hex", "url"),
            e("Recipe", "Encode / Decode", "Recipe", Provider.CODECS, "chain", "layers"),
            e("HMAC", "Encode / Decode", "HMAC", Provider.CODECS, "mac"),
            e("File Hash", "Encode / Decode", "File Hash", Provider.CODECS, "hash", "checksum", "sha256sum"),
            e("AES / ChaCha20", "Ciphers", "AES / ChaCha20", Provider.CODECS, "aes", "chacha", "gcm", "encrypt-text"),
            e("Blowfish", "Ciphers", "Blowfish", Provider.CODECS, "bf"),
            e("JWT Verifier", "JWT", "Verifier", Provider.INSPECTOR, "jwt", "jwt-verify", "token"),
            e("JWT Builder", "JWT", "Builder", Provider.INSPECTOR, "jwt-builder", "jwt-sign", "jwt-create"),
            e("X.509 Inspector", "Certificates", "X.509 Inspector", Provider.INSPECTOR, "x509", "cert", "certificate", "csr", "p12", "tls"),
            e("Key Generator", "Certificates", "Key Generator", Provider.INSPECTOR, "keygen", "self-signed", "keypair"),
            e("Decrypt", "GPG", "Decrypt", Provider.GPG, "gpg", "gpg-decrypt", "pgp"),
            e("Encrypt", "GPG", "Encrypt", Provider.GPG, "gpg-encrypt"),
            e("Sign", "GPG", "Sign", Provider.GPG, "gpg-sign"),
            e("Verify", "GPG", "Verify", Provider.GPG, "gpg-verify", "signature"),
            e("Keys", "GPG", "Keys", Provider.GPG, "gpg-keys", "keyring"),
            e("Hide Message", "Steganography", "Hide Message", Provider.STEGO, "stego", "steganography", "hide", "lsb"),
            e("Reveal Message", "Steganography", "Reveal Message", Provider.STEGO, "reveal", "unhide", "extract"),
            e("Analyze Image", "Steganography", "Analyze Image", Provider.STEGO, "steganalysis", "analyze", "chi-square"),
            e("History", "Session", "History", Provider.HISTORY, "recent", "undo", "log"));

    static final String DEFAULT_SCREEN = "Text Codecs";

    private ScreenCatalog() {
    }

    private static Entry e(String title, String group, String label, Provider provider, String... aliases) {
        return new Entry(title, group, label, provider, List.of(aliases));
    }

    static Optional<Entry> byTitle(String title) {
        return ENTRIES.stream().filter(x -> x.title().equals(title)).findFirst();
    }

    static List<Entry> inGroup(String group) {
        return ENTRIES.stream().filter(x -> x.group().equals(group)).toList();
    }

    /** Entries matching every word of {@code query} against label, group, title or aliases. Empty query: all. */
    static List<Entry> filter(String query) {
        String[] words = norm(query).isEmpty() ? new String[0] : query.toLowerCase(Locale.ROOT).trim().split("\\s+");
        return ENTRIES.stream().filter(x -> Arrays.stream(words).allMatch(w -> haystack(x).contains(w))).toList();
    }

    /** Finds a screen from a {@code --tool=} value: an alias or title, ignoring case, spaces and punctuation. */
    static Optional<Entry> resolve(String tool) {
        if (tool == null || tool.isBlank()) {
            return Optional.empty();
        }
        String t = norm(tool);
        return ENTRIES.stream()
                .filter(x -> norm(x.title()).equals(t) || x.aliases().stream().anyMatch(a -> norm(a).equals(t)))
                .findFirst();
    }

    /** The value of {@code --tool=NAME} or {@code --tool NAME} in program arguments, if any. */
    static Optional<String> toolArgument(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--tool=")) {
                return Optional.of(args[i].substring(7));
            }
            if (args[i].equals("--tool") && i + 1 < args.length) {
                return Optional.of(args[i + 1]);
            }
        }
        return Optional.empty();
    }

    private static String haystack(Entry x) {
        return (x.label() + " " + x.group() + " " + x.title() + " " + String.join(" ", x.aliases())).toLowerCase(Locale.ROOT);
    }

    private static String norm(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
}
