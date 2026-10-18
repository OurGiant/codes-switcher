package com.ourgiant.crypt.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BlowfishCodecTest {

    @Test
    void roundTripWithCrc() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String cipher = codec.encrypt("Hello, World!", true);
        assertEquals("Hello, World!", codec.decrypt(cipher, true));
    }

    @Test
    void roundTripWithoutCrc() {
        // Without CRC framing there is no length marker, so the decrypted value is
        // space-padded up to the 8-byte block boundary. Trim to compare the content.
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String cipher = codec.encrypt("Hello, World!", false);
        assertEquals("Hello, World!", codec.decrypt(cipher, false).trim());
    }

    @Test
    void cipherTextIsUppercaseHex() {
        BlowfishCodec codec = new BlowfishCodec("k");
        String cipher = codec.encrypt("abc", true);
        assertTrue(cipher.matches("[0-9A-F]+"), "cipher should be uppercase hex: " + cipher);
    }

    @Test
    void differentKeysProduceDifferentCipherText() {
        String cipherA = new BlowfishCodec("key-a").encrypt("same input", true);
        String cipherB = new BlowfishCodec("key-b").encrypt("same input", true);
        assertNotEquals(cipherA, cipherB);
    }

    @Test
    void crcDecryptRejectsTamperedCipherText() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String cipher = codec.encrypt("sensitive", true);
        // Flip the last hex nibble to corrupt the final block.
        char last = cipher.charAt(cipher.length() - 1);
        char flipped = (last == '0') ? '1' : '0';
        String tampered = cipher.substring(0, cipher.length() - 1) + flipped;
        assertEquals("", codec.decrypt(tampered, true));
    }

    @Test
    void crcDecryptRejectsTruncatedCipherText() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String cipher = codec.encrypt("sensitive", true);
        // Drop a nibble so the length is no longer a whole number of blocks.
        assertEquals("", codec.decrypt(cipher.substring(0, cipher.length() - 1), true));
    }

    @Test
    void unicodeRoundTrip() {
        BlowfishCodec codec = new BlowfishCodec("key");
        String input = "caf\u00e9 \u00fcber \u2603"; // café über ☃
        assertEquals(input, codec.decrypt(codec.encrypt(input, true), true));
    }

    @Test
    void emptyKeyIsAccepted() {
        BlowfishCodec codec = new BlowfishCodec("");
        assertEquals("data", codec.decrypt(codec.encrypt("data", true), true));
    }

    @Test
    void nullKeyRejected() {
        assertThrows(IllegalArgumentException.class, () -> new BlowfishCodec(null));
    }

    @Test
    void nullInputsRejected() {
        BlowfishCodec codec = new BlowfishCodec("k");
        assertThrows(IllegalArgumentException.class, () -> codec.encrypt(null, true));
        assertThrows(IllegalArgumentException.class, () -> codec.decrypt(null, true));
    }

    /**
     * Fixed ciphertext produced by the reference Blowfish implementation this codec
     * is based on, for key {@code secret-key-123} and plaintext {@code Hello, World!}.
     * Guards against any accidental change to the algorithm or framing.
     */
    @Test
    void decryptsKnownCrcVector() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String known = "8BDB38C1D0A9807F88118EBAEFC2F0F5C409750B58B47090D468E34667D40EF5DBB5FE0B2EA19404";
        assertEquals("Hello, World!", codec.decrypt(known, true));
    }

    @Test
    void decryptsKnownNonCrcVector() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        String known = "8BDB38C1D0A9807F88118EBAEFC2F0F5C409750B58B4709042FF63E57FBF29BF";
        assertEquals("Hello, World!", codec.decrypt(known, false).trim());
    }

    @Test
    void encryptMatchesKnownCrcVector() {
        BlowfishCodec codec = new BlowfishCodec("secret-key-123");
        assertEquals(
                "8BDB38C1D0A9807F88118EBAEFC2F0F5C409750B58B47090D468E34667D40EF5DBB5FE0B2EA19404",
                codec.encrypt("Hello, World!", true));
    }
}
