package com.ourgiant.crypt.crypto.classic;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class VigenereCrackerTest {

    static final String PLAIN = """
            The old curator had left a trail of clues across the museum, hidden in plain sight among the paintings \
            and the statues. Each clue pointed to another, and the young professor followed them through the long \
            galleries until the night guards began their rounds. He knew that the answer lay somewhere beneath the \
            great glass pyramid, where the light of the moon fell upon the stone floor. Nobody else had noticed the \
            small marks carved into the frames, nor the way the letters on the old map seemed to repeat themselves \
            in a pattern that only a patient reader could see. By morning he had written down every word, and the \
            message began to make sense at last.""";

    @ParameterizedTest
    @ValueSource(strings = {"LEMONS", "GRAIL", "SOPHIE", "TEMPLAR", "CRYPTEX"})
    void recoversTheKey(String key) {
        String cipher = ClassicCiphers.vigenereEncrypt(PLAIN, key);
        VigenereCracker.Result r = VigenereCracker.crack(cipher, 20, 5);
        assertTrue(r.letters() > 400);
        assertEquals(key, r.candidates().get(0).key());
        assertEquals(PLAIN, r.candidates().get(0).plaintext());
    }

    @Test
    void trueLengthHasEnglishLikeIoc() {
        String cipher = ClassicCiphers.vigenereEncrypt(PLAIN, "TEMPLAR");
        VigenereCracker.Result r = VigenereCracker.crack(cipher, 20, 5);
        double ioc7 = r.lengths().get(6).ioc();
        double ioc5 = r.lengths().get(4).ioc();
        assertTrue(ioc7 > 0.055, "IoC at 7 = " + ioc7);
        assertTrue(ioc5 < 0.05, "IoC at 5 = " + ioc5);
        assertTrue(r.lengths().get(6).kasiski() > 0);
    }

    @Test
    void shortestPeriod() {
        assertEquals("LEMON", VigenereCracker.shortestPeriod("LEMONLEMON"));
        assertEquals("AB", VigenereCracker.shortestPeriod("ABABAB"));
        assertEquals("ABC", VigenereCracker.shortestPeriod("ABC"));
    }

    @Test
    void tooShortIsAClearError() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> VigenereCracker.crack("abc def", 10, 3));
        assertTrue(e.getMessage().contains("more ciphertext"));
    }
}
