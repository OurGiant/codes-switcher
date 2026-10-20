package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.prefs.Preferences;

import static org.junit.jupiter.api.Assertions.*;

class ScreenCatalogTest {

    @Test
    void everyScreenHasAUniqueTitleAndAKnownGroup() {
        assertEquals(ScreenCatalog.ENTRIES.size(),
                new HashSet<>(ScreenCatalog.ENTRIES.stream().map(ScreenCatalog.Entry::title).toList()).size());
        assertTrue(ScreenCatalog.ENTRIES.stream().allMatch(e -> ScreenCatalog.GROUPS.contains(e.group())));
        for (String g : ScreenCatalog.GROUPS) {
            assertFalse(ScreenCatalog.inGroup(g).isEmpty(), g + " has screens");
        }
        assertTrue(ScreenCatalog.byTitle(ScreenCatalog.DEFAULT_SCREEN).isPresent());
    }

    @Test
    void aliasesDontCollide() {
        var seen = new HashSet<String>();
        for (var e : ScreenCatalog.ENTRIES) {
            for (String a : e.aliases()) {
                assertTrue(seen.add(a.toLowerCase()), "duplicate alias " + a);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({
            "gpg, Decrypt", "GPG-Encrypt, Encrypt", "jwt, JWT Verifier", "jwt-builder, JWT Builder",
            "x509, X.509 Inspector", "X.509 Inspector, X.509 Inspector", "keygen, Key Generator",
            "hash, File Hash", "aes, AES / ChaCha20", "text codecs, Text Codecs", "Recipe, Recipe",
            "enigma, Enigma", "imitation, Enigma", "ottendorf, Book Cipher", "book, Book Cipher", "atbash, Substitution",
            "caesar, Substitution", "rot, Substitution", "vigenere, Substitution", "crack, Vigenère Cracker",
            "vigenere-crack, Vigenère Cracker"})
    void resolvesToolArgument(String tool, String title) {
        assertEquals(Optional.of(title), ScreenCatalog.resolve(tool).map(ScreenCatalog.Entry::title));
    }

    @Test
    void classicCiphersComeRightAfterCiphers() {
        assertEquals(ScreenCatalog.GROUPS.indexOf("Ciphers") + 1, ScreenCatalog.GROUPS.indexOf("Classic Ciphers"));
        assertEquals(List.of("Enigma", "Book Cipher", "Substitution", "Vigenère Cracker"),
                ScreenCatalog.inGroup("Classic Ciphers").stream().map(ScreenCatalog.Entry::title).toList());
        assertEquals(8, ScreenCatalog.GROUPS.indexOf("Session") + 1);
    }

    @Test
    void unknownToolIsEmpty() {
        assertTrue(ScreenCatalog.resolve("teleporter").isEmpty());
        assertTrue(ScreenCatalog.resolve("").isEmpty());
        assertTrue(ScreenCatalog.resolve(null).isEmpty());
    }

    @Test
    void readsToolFromArgs() {
        assertEquals(Optional.of("gpg"), ScreenCatalog.toolArgument(new String[]{"--tool=gpg"}));
        assertEquals(Optional.of("jwt"), ScreenCatalog.toolArgument(new String[]{"-x", "--tool", "jwt"}));
        assertTrue(ScreenCatalog.toolArgument(new String[]{"--tool"}).isEmpty());
        assertTrue(ScreenCatalog.toolArgument(new String[0]).isEmpty());
    }

    @Test
    void searchMatchesLabelsGroupsAndAliases() {
        assertEquals(ScreenCatalog.ENTRIES, ScreenCatalog.filter(""));
        assertEquals(ScreenCatalog.ENTRIES, ScreenCatalog.filter("   "));
        assertEquals(List.of("JWT Verifier", "JWT Builder"), titles("jwt"));
        assertEquals(List.of("Verify"), titles("gpg ver"));
        assertTrue(titles("sha256sum").contains("File Hash"));
        assertTrue(titles("csr").contains("X.509 Inspector"));
        assertTrue(titles("nothing-matches-this").isEmpty());
    }

    @Test
    void windowPreferencesRoundTrip() throws Exception {
        Preferences node = Preferences.userRoot().node("codes-switcher-test-" + System.nanoTime());
        try {
            AppPreferences p = new AppPreferences(node);
            assertNull(p.getWindowBounds());
            assertEquals("", p.getLastScreen());
            assertEquals(210, p.getSidebarWidth(210));
            p.setWindowBounds(new java.awt.Rectangle(10, 20, 1100, 760));
            p.setLastScreen("Keys");
            p.setSidebarWidth(240);
            p.setMaximized(true);
            assertEquals(new java.awt.Rectangle(10, 20, 1100, 760), p.getWindowBounds());
            assertEquals("Keys", p.getLastScreen());
            assertEquals(240, p.getSidebarWidth(210));
            assertTrue(p.isMaximized());
            node.put("mainWindow.bounds", "garbage");
            assertNull(p.getWindowBounds());
        } finally {
            node.removeNode();
        }
    }

    private static List<String> titles(String q) {
        return ScreenCatalog.filter(q).stream().map(ScreenCatalog.Entry::title).toList();
    }
}
