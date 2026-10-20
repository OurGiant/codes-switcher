package com.ourgiant.crypt.crypto;

import com.ourgiant.crypt.crypto.PasswordStrength.Rating;
import com.ourgiant.crypt.crypto.PasswordStrength.Result;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class PasswordStrengthTest {

    @ParameterizedTest
    @ValueSource(strings = {"password", "123456", "qwerty", "Password", "P@ssw0rd", "joshua", "aaaaaaaa", "abcdefgh", "12345678"})
    void commonAndPatternPasswordsAreVeryWeak(String pw) {
        Result r = PasswordStrength.estimate(pw);
        assertEquals(Rating.VERY_WEAK, r.rating(), pw + " → " + r.bits() + " bits");
    }

    @Test
    void theMostCommonPasswordSaysSo() {
        assertTrue(PasswordStrength.estimate("password").warnings().get(0).contains("most common"));
    }

    @Test
    void lookAlikeSwapsAreSeenThrough() {
        Result r = PasswordStrength.estimate("P@ssw0rd");
        assertTrue(r.bits() < 12, "bits " + r.bits());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("look-alikes")));
    }

    @Test
    void patternsAreNamed() {
        assertTrue(PasswordStrength.estimate("zzzzzzzzzzzzzz").warnings().stream().anyMatch(w -> w.contains("Repeated")));
        assertTrue(PasswordStrength.estimate("Xq!abcdefg").warnings().stream().anyMatch(w -> w.contains("Sequences")));
        assertTrue(PasswordStrength.estimate("Xq!asdfghj").warnings().stream().anyMatch(w -> w.contains("Keyboard")));
        assertTrue(PasswordStrength.estimate("Xq!v1987").warnings().stream().anyMatch(w -> w.contains("Years")));
    }

    @Test
    void wordsAndPatternsCostLessThanRandomCharacters() {
        double pattern = PasswordStrength.estimate("dragon1987").bits();
        double random = PasswordStrength.estimate("kx7qw2mzpv").bits();
        assertTrue(pattern < 30, "dragon1987: " + pattern);
        assertTrue(random > 45, "random: " + random);
    }

    @Test
    void randomLongPasswordsAreStrong() {
        assertEquals(Rating.VERY_STRONG, PasswordStrength.estimate("Tq9#vL2!mZ8$wR4^xK").rating());
        // Four random words: the classic passphrase still beats a short complex password.
        assertTrue(PasswordStrength.estimate("orbit-velvet-cactus-lantern").bits()
                > PasswordStrength.estimate("Tr0ub4dor&3").bits());
        // The xkcd example: a capitalised word with look-alike swaps and two extra characters.
        assertTrue(PasswordStrength.estimate("Tr0ub4dor&3").rating().ordinal() <= Rating.WEAK.ordinal());
    }

    @Test
    void shortPasswordsAreCappedAtWeak() {
        assertTrue(PasswordStrength.estimate("Zq#8vX!").rating().ordinal() <= Rating.WEAK.ordinal());
        assertTrue(PasswordStrength.estimate("Zq#8vX!").warnings().stream().anyMatch(w -> w.contains("12 characters")));
    }

    @Test
    void crackTimesGetFasterWithFasterAttacks() {
        Result r = PasswordStrength.estimate("correct horse battery staple");
        assertEquals(4, r.crackTimes().size());
        for (int i = 1; i < r.crackTimes().size(); i++) {
            assertTrue(r.crackTimes().get(i).seconds() < r.crackTimes().get(i - 1).seconds());
        }
    }

    @Test
    void emptyAndHugeInputsAreHandled() {
        Result empty = PasswordStrength.estimate("");
        assertEquals(0, empty.bits());
        assertEquals(Rating.VERY_WEAK, empty.rating());
        assertTrue(PasswordStrength.estimate("x".repeat(10_000)).bits() > 0);
        assertTrue(PasswordStrength.estimate("é漢字ü🙂").bits() > 20);
    }

    @Test
    void durationsReadNaturally() {
        assertEquals("less than a second", PasswordStrength.formatDuration(0.2));
        assertEquals("1 second", PasswordStrength.formatDuration(1.2));
        assertEquals("3 minutes", PasswordStrength.formatDuration(180));
        assertEquals("2 days", PasswordStrength.formatDuration(2 * 86400));
        assertEquals("about 5 years", PasswordStrength.formatDuration(5 * 86400 * 365.25));
        assertEquals("centuries", PasswordStrength.formatDuration(1e12));
    }

    @Test
    void caseBits() {
        assertEquals(0, PasswordStrength.caseBits("dragon"));
        assertEquals(1, PasswordStrength.caseBits("Dragon"));
        assertEquals(1, PasswordStrength.caseBits("DRAGON"));
        assertTrue(PasswordStrength.caseBits("dRaGoN") > 2);
    }
}
