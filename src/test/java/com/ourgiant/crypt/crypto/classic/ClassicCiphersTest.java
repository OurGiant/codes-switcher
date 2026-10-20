package com.ourgiant.crypt.crypto.classic;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ClassicCiphersTest {

    @Test
    void atbash() {
        assertEquals("Zyx, ABC!", ClassicCiphers.atbash("Abc, ZYX!"));
        assertEquals("Hello 123", ClassicCiphers.atbash(ClassicCiphers.atbash("Hello 123")));
    }

    @Test
    void caesar() {
        assertEquals("Khoor, Zruog!", ClassicCiphers.caesar("Hello, World!", 3));
        assertEquals("Hello, World!", ClassicCiphers.caesar("Khoor, Zruog!", -3));
        assertEquals(ClassicCiphers.caesar("abc", 1), ClassicCiphers.caesar("abc", 27));
        assertEquals(ClassicCiphers.caesar("abc", -1), ClassicCiphers.caesar("abc", 25));
        assertEquals("Uryyb", ClassicCiphers.caesar("Hello", 13));
    }

    @Test
    void tryAll26RanksTheRightShiftFirst() {
        String cipher = ClassicCiphers.caesar("The secret is hidden beneath the stone in the old chapel garden.", 11);
        List<ClassicCiphers.CaesarCandidate> all = ClassicCiphers.caesarAll(cipher);
        assertEquals(26, all.size());
        assertEquals(11, all.get(0).shift());
        assertEquals("The secret is hidden beneath the stone in the old chapel garden.", all.get(0).text());
    }

    @Test
    void vigenereKeepsCaseAndSkipsNonLetters() {
        // Classic textbook example.
        assertEquals("LXFOPVEFRNHR", ClassicCiphers.vigenereEncrypt("ATTACKATDAWN", "LEMON"));
        assertEquals("Lxfo pv-ef rnhr!", ClassicCiphers.vigenereEncrypt("Atta ck-at dawn!", "lemon"));
        assertEquals("Atta ck-at dawn!", ClassicCiphers.vigenereDecrypt("Lxfo pv-ef rnhr!", "Le Mon"));
        assertThrows(IllegalArgumentException.class, () -> ClassicCiphers.vigenereEncrypt("x", "123"));
    }

    @Test
    void englishScoreFavoursEnglish() {
        assertTrue(ClassicCiphers.englishScore("the quick brown fox jumps over the lazy dog")
                < ClassicCiphers.englishScore("qzx jvk wqp zzx qjq xkz vvq"));
        assertEquals(Double.MAX_VALUE, ClassicCiphers.englishScore("123 !"));
    }
}
