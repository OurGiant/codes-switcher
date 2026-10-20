package com.ourgiant.crypt.crypto.classic;

import com.ourgiant.crypt.crypto.classic.Enigma.Reflector;
import com.ourgiant.crypt.crypto.classic.Enigma.Rotor;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EnigmaTest {

    private static Enigma machine(String start) {
        return new Enigma(List.of(Rotor.I, Rotor.II, Rotor.III), Reflector.B, new int[]{1, 1, 1}, start, "");
    }

    @Test
    void basicVector() {
        Enigma e = machine("AAA");
        assertEquals("BDZGO", e.process("AAAAA", false, false));
        assertEquals("AAF", e.positions());
    }

    @Test
    void encryptIsDecrypt() {
        String plain = "Hello, World! The quick brown fox jumps over the lazy dog.";
        List<Rotor> rotors = List.of(Rotor.VI, Rotor.VIII, Rotor.IV);
        String cipher = new Enigma(rotors, Reflector.C, new int[]{5, 17, 26}, "QMZ", "AB CD EF").process(plain, true, false);
        String back = new Enigma(rotors, Reflector.C, new int[]{5, 17, 26}, "QMZ", "AB CD EF").process(cipher, true, false);
        assertEquals(plain.toUpperCase(), back);
        assertNotEquals(plain.toUpperCase(), cipher);
        assertEquals(plain.replaceAll("[A-Za-z]", ""), cipher.replaceAll("[A-Z]", ""));
    }

    @Test
    void dropsNonLettersWhenAsked() {
        assertEquals("BDZGO", machine("AAA").process("AA-A a!a", false, false));
    }

    @Test
    void neverEncryptsALetterToItself() {
        Enigma e = machine("XYZ");
        for (int i = 0; i < 2000; i++) {
            assertNotEquals('E', e.press('E'));
        }
    }

    @Test
    void doubleStep() {
        // Rotor III turns over from V to W; the middle rotor then steps on two key presses in a row.
        Enigma e = machine("ADU");
        StringBuilder seen = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            e.press('A');
            seen.append(e.positions()).append(' ');
        }
        assertEquals("ADV AEW BFX BFY ", seen.toString());
        Enigma f = machine("ADV");
        f.press('A');
        assertEquals("AEW", f.positions());
        f.press('A');
        assertEquals("BFX", f.positions());
    }

    @Test
    void rotorsSixToEightHaveTwoNotches() {
        assertEquals("ZM", Rotor.VI.notches());
        assertEquals("ZM", Rotor.VII.notches());
        assertEquals("ZM", Rotor.VIII.notches());
        Enigma m = new Enigma(List.of(Rotor.I, Rotor.II, Rotor.VI), Reflector.B, new int[]{1, 1, 1}, "AAM", "");
        m.press('A');
        assertEquals("ABN", m.positions());
        Enigma z = new Enigma(List.of(Rotor.I, Rotor.II, Rotor.VI), Reflector.B, new int[]{1, 1, 1}, "AAZ", "");
        z.press('A');
        assertEquals("ABA", z.positions());
        Enigma q = new Enigma(List.of(Rotor.I, Rotor.II, Rotor.VI), Reflector.B, new int[]{1, 1, 1}, "AAQ", "");
        q.press('A');
        assertEquals("AAR", q.positions());
    }

    @Test
    void operationBarbarossa() {
        String cipher = "EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT TDEIS MDICA GYKUA "
                + "CTCDO MOHWX MUUIA UBSTS LRNBZ SZWNR FXWFY SSXJZ VIJHI DISHP RKLKA YUPAD TXQSP INQMA TLPIF SVKDA SCTAC DPBOP VHJK";
        Enigma e = new Enigma(List.of(Rotor.II, Rotor.IV, Rotor.V), Reflector.B, Enigma.parseRings("02 21 12"), "BLA",
                "AV BS CG DL FU HZ IN KM OW RX");
        String plain = e.process(cipher, false, false);
        assertTrue(plain.startsWith("AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNG"
                + "XDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENXANGRIFFXINFXRGTX"), plain);
        assertArrayEquals(Enigma.parseRings("BUL"), Enigma.parseRings("02 21 12"));
    }

    @Test
    void groupsInFives() {
        assertEquals("BDZGO WCXLT", machine("AAA").process("aaaaa aaaaa", true, true));
    }

    @Test
    void rejectsBadSettings() {
        assertThrows(IllegalArgumentException.class, () -> Enigma.parsePlugboard("AB AC"));
        assertThrows(IllegalArgumentException.class, () -> Enigma.parsePlugboard("AA"));
        assertThrows(IllegalArgumentException.class, () -> Enigma.parsePlugboard("ABC"));
        assertThrows(IllegalArgumentException.class, () -> Enigma.parsePlugboard("AB CD EF GH IJ KL MN OP QR ST UV WX YZ AB"));
        assertEquals(List.of("AB", "CD"), Enigma.parsePlugboard(" ab, cd "));
        assertEquals(13, Enigma.parsePlugboard("AB CD EF GH IJ KL MN OP QR ST UV WX YZ").size());
        assertThrows(IllegalArgumentException.class, () -> machine("AA"));
        assertThrows(IllegalArgumentException.class, () -> Enigma.parseRings("0 1 1"));
        assertThrows(IllegalArgumentException.class, () -> Enigma.parseRings("1 1"));
        assertThrows(IllegalArgumentException.class,
                () -> new Enigma(List.of(Rotor.I, Rotor.I, Rotor.III), Reflector.B, new int[]{1, 1, 1}, "AAA", ""));
        assertArrayEquals(new int[]{2, 21, 12}, Enigma.parseRings("B U L"));
    }
}
