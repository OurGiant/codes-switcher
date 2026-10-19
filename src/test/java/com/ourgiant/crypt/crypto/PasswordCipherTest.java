package com.ourgiant.crypt.crypto;

import com.ourgiant.crypt.crypto.PasswordCipher.Algorithm;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordCipherTest {

    // Low iteration count keeps the suite fast; the format records the count.
    private final PasswordCipher cipher = new PasswordCipher(1_000);
    private static final char[] PW = "correct horse".toCharArray();

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void roundTrip(Algorithm alg) throws Exception {
        String text = "Hello, wörld! 🔐\nline two";
        String enc = cipher.encrypt(text, PW, alg);
        assertEquals(text, cipher.decrypt(enc, PW));
        assertEquals(alg, PasswordCipher.algorithmOf(enc));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void emptyPlaintextRoundTrips(Algorithm alg) throws Exception {
        assertEquals("", cipher.decrypt(cipher.encrypt("", PW, alg), PW));
    }

    @Test
    void sameInputEncryptsDifferentlyEachTime() throws Exception {
        String a = cipher.encrypt("same", PW, Algorithm.AES_256_GCM);
        String b = cipher.encrypt("same", PW, Algorithm.AES_256_GCM);
        assertNotEquals(a, b);
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void wrongPasswordFails(Algorithm alg) throws Exception {
        String enc = cipher.encrypt("secret", PW, alg);
        assertThrows(PasswordCipher.AuthenticationException.class,
                () -> cipher.decrypt(enc, "wrong".toCharArray()));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void tamperedCiphertextFails(Algorithm alg) throws Exception {
        byte[] raw = Base64.getDecoder().decode(cipher.encrypt("secret", PW, alg));
        raw[raw.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThrows(PasswordCipher.AuthenticationException.class, () -> cipher.decrypt(tampered, PW));
    }

    @Test
    void tamperedHeaderSaltFails() throws Exception {
        byte[] raw = Base64.getDecoder().decode(cipher.encrypt("secret", PW, Algorithm.AES_256_GCM));
        raw[10] ^= 1; // inside the salt
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThrows(PasswordCipher.AuthenticationException.class, () -> cipher.decrypt(tampered, PW));
    }

    @Test
    void switchingAlgorithmIdFails() throws Exception {
        byte[] raw = Base64.getDecoder().decode(cipher.encrypt("secret", PW, Algorithm.AES_256_GCM));
        raw[3] = 2; // claim ChaCha20
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThrows(PasswordCipher.AuthenticationException.class, () -> cipher.decrypt(tampered, PW));
    }

    @Test
    void rejectsNonBase64() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> cipher.decrypt("not base64 !!!", PW));
        assertTrue(e.getMessage().contains("Base64"));
    }

    @Test
    void rejectsForeignData() {
        String foreign = Base64.getEncoder().encodeToString(new byte[64]);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> cipher.decrypt(foreign, PW));
        assertTrue(e.getMessage().contains("header"));
    }

    @Test
    void rejectsHugeIterationCount() throws Exception {
        byte[] raw = Base64.getDecoder().decode(cipher.encrypt("secret", PW, Algorithm.AES_256_GCM));
        raw[4] = 0x7f; // iterations high byte -> ~2 billion
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(tampered, PW));
    }

    @Test
    void requiresPassword() {
        assertThrows(IllegalArgumentException.class,
                () -> cipher.encrypt("x", new char[0], Algorithm.AES_256_GCM));
    }

    @Test
    void toleratesWrappedBase64() throws Exception {
        String enc = cipher.encrypt("wrapped", PW, Algorithm.CHACHA20_POLY1305);
        String wrapped = enc.substring(0, 20) + "\n" + enc.substring(20) + "\n";
        assertEquals("wrapped", cipher.decrypt(wrapped, PW));
    }

    @Test
    void defaultIterationsDecryptable() throws Exception {
        PasswordCipher real = new PasswordCipher();
        String enc = real.encrypt("real", PW, Algorithm.AES_256_GCM);
        // A cipher configured differently still decrypts: count is read from the data.
        assertEquals("real", cipher.decrypt(enc, PW));
    }
}
