package com.ourgiant.crypt.crypto.classic;

import com.ourgiant.crypt.crypto.classic.BookCipher.Mode;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BookCipherTest {

    static final String BOOK = """
            When in the Course of human events, it becomes necessary for one people
            to dissolve the political bands which have connected them with another,

            "Freedom!" said the people; the people said freedom.""";

    private static BookCipher book(long seed) {
        return new BookCipher(BOOK, new Random(seed));
    }

    @Test
    void wordModeRoundTrips() {
        BookCipher b = book(1);
        String codes = b.encode("The People, said FREEDOM", Mode.WORD);
        assertTrue(codes.matches("\\d+-\\d+( \\d+-\\d+){3}"), codes);
        assertEquals("the people said freedom", b.decode(codes));
    }

    @Test
    void codesAreOneBasedAndIgnorePunctuation() {
        BookCipher b = book(1);
        assertEquals("when", b.decode("1-1"));
        assertEquals("course", b.decode("1-4"));
        assertEquals("freedom", b.decode("4-1"));
        assertEquals("people", b.decode("4-4"));
        assertEquals("events", b.decode("1-7"));
        assertEquals("e", b.decode("1-1-3"));
        assertEquals("when course", b.decode("1.1, 1:4"));
    }

    @Test
    void repeatedWordsGetDifferentCodes() {
        BookCipher b = book(42);
        Set<String> codes = new HashSet<>();
        for (int i = 0; i < 30; i++) {
            codes.add(b.encode("people", Mode.WORD));
        }
        assertTrue(codes.size() > 1, codes.toString());
        assertTrue(codes.stream().allMatch(c -> b.decode(c).equals("people")));
    }

    @Test
    void sameSeedSameCodes() {
        assertEquals(book(7).encode("the people said", Mode.WORD), book(7).encode("the people said", Mode.WORD));
    }

    @Test
    void letterModeRoundTrips() {
        BookCipher b = book(3);
        String codes = b.encode("Hide it now", Mode.LETTER);
        assertTrue(codes.matches("(\\d+-\\d+-\\d+|/)( (\\d+-\\d+-\\d+|/))*"), codes);
        assertEquals(2, codes.chars().filter(c -> c == '/').count());
        assertEquals("hide it now", b.decode(codes));
    }

    @Test
    void missingWordOrLetterIsNamed() {
        BookCipher b = book(1);
        IllegalArgumentException w = assertThrows(IllegalArgumentException.class, () -> b.encode("the treasure", Mode.WORD));
        assertTrue(w.getMessage().contains("\"treasure\""), w.getMessage());
        IllegalArgumentException l = assertThrows(IllegalArgumentException.class, () -> b.encode("jazz", Mode.LETTER));
        assertTrue(l.getMessage().contains("\"j\""), l.getMessage());
    }

    @Test
    void outOfRangeCodesAreClear() {
        BookCipher b = book(1);
        assertTrue(assertThrows(IllegalArgumentException.class, () -> b.decode("9-1")).getMessage().contains("4 lines"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> b.decode("1-99")).getMessage().contains("line 1 has 13 words"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> b.decode("3-1")).getMessage().contains("line 3 has 0 words"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> b.decode("1-1-9")).getMessage().contains("(\"when\") has 4 letters"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> b.decode("hello")).getMessage().contains("Can't read code"));
    }

    @Test
    void emptyBookIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new BookCipher("  \n ... \n", new Random()));
    }
}
