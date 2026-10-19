package com.ourgiant.crypt.crypto;

import com.ourgiant.crypt.crypto.BlowfishCbc.Encoding;
import com.ourgiant.crypt.crypto.BlowfishCbc.Padding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class BlowfishCbcTest {

    private static final byte[] KEY = HexFormat.of().parseHex("0123456789abcdeff0e1d2c3b4a59687");
    private static final byte[] IV = HexFormat.of().parseHex("fedcba9876543210");

    /** echo -n "hello blowfish" | openssl enc -bf-cbc -K 0123...9687 -iv fedcba9876543210 -provider legacy */
    @Test
    void matchesOpenSsl() throws Exception {
        assertEquals("0033254EFBE4C9739F8353A38329171C",
                BlowfishCbc.encrypt("hello blowfish", KEY, IV, Padding.PKCS5, Encoding.HEX));
        assertEquals("ADMlTvvkyXOfg1OjgykXHA==",
                BlowfishCbc.encrypt("hello blowfish", KEY, IV, Padding.PKCS5, Encoding.BASE64));
        assertEquals("hello blowfish",
                BlowfishCbc.decrypt("ADMlTvvkyXOfg1OjgykXHA==", KEY, IV, Padding.PKCS5, Encoding.BASE64));
    }

    /** Eric Young's Blowfish CBC test vector (zero-padded "7654321 Now is the time for "). */
    @Test
    void ericYoungCbcVector() throws Exception {
        String plain = "7654321 Now is the time for ";
        assertEquals("6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC",
                BlowfishCbc.encrypt(plain, KEY, IV, Padding.ZERO, Encoding.HEX));
        assertEquals(plain, BlowfishCbc.decrypt(
                "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC",
                KEY, IV, Padding.ZERO, Encoding.HEX));
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    void roundTrip(Padding padding) throws Exception {
        String text = padding == Padding.NONE ? "exactly 16 bytes" : "Grüße 🔐";
        for (Encoding enc : Encoding.values()) {
            String ct = BlowfishCbc.encrypt(text, KEY, IV, padding, enc);
            assertEquals(text, BlowfishCbc.decrypt(ct, KEY, IV, padding, enc));
        }
    }

    @Test
    void noPaddingRequiresBlockMultiple() {
        assertThrows(IllegalArgumentException.class,
                () -> BlowfishCbc.encrypt("short", KEY, IV, Padding.NONE, Encoding.HEX));
    }

    @Test
    void wrongKeyGivesPaddingError() throws Exception {
        String ct = BlowfishCbc.encrypt("hello blowfish", KEY, IV, Padding.PKCS5, Encoding.HEX);
        byte[] other = "another key".getBytes();
        // A wrong key almost always breaks PKCS#5 padding; if not, the text must differ.
        try {
            assertNotEquals("hello blowfish", BlowfishCbc.decrypt(ct, other, IV, Padding.PKCS5, Encoding.HEX));
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("padding"));
        }
    }

    @Test
    void validatesKeyIvAndInput() {
        assertThrows(IllegalArgumentException.class,
                () -> BlowfishCbc.encrypt("x", new byte[3], IV, Padding.PKCS5, Encoding.HEX));
        assertThrows(IllegalArgumentException.class,
                () -> BlowfishCbc.encrypt("x", new byte[57], IV, Padding.PKCS5, Encoding.HEX));
        assertThrows(IllegalArgumentException.class, () -> BlowfishCbc.parseIv("0011"));
        assertThrows(IllegalArgumentException.class, () -> BlowfishCbc.parseIv("zz11223344556677"));
        assertThrows(IllegalArgumentException.class,
                () -> BlowfishCbc.decrypt("ABCD", KEY, IV, Padding.PKCS5, Encoding.HEX));
        assertThrows(IllegalArgumentException.class,
                () -> BlowfishCbc.decrypt("nothex!", KEY, IV, Padding.PKCS5, Encoding.HEX));
    }

    @Test
    void randomIvIsEightBytesAndVaries() {
        assertEquals(8, BlowfishCbc.randomIv().length);
        assertFalse(java.util.Arrays.equals(BlowfishCbc.randomIv(), BlowfishCbc.randomIv()));
        assertArrayEquals(IV, BlowfishCbc.parseIv("FE DC BA 98 76 54 32 10"));
    }
}
