package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwksKeysTest {

    @Test
    void findsAndRebuildsAnRsaKeyByKid() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey rsaKey = (RSAPublicKey) kp.getPublic();
        String jwks = """
            {"keys": [
              {"kty":"RSA","kid":"key-1","n":"%s","e":"%s"}
            ]}
            """.formatted(
            base64Url(rsaKey.getModulus().toByteArray()),
            base64Url(rsaKey.getPublicExponent().toByteArray()));

        PublicKey found = JwksKeys.findKey(jwks, "key-1");

        assertEquals(kp.getPublic(), found);
    }

    @Test
    void findsAndRebuildsAnEcKeyByKid() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPublicKey ecKey = (ECPublicKey) kp.getPublic();
        String jwks = """
            {"keys": [
              {"kty":"EC","kid":"key-2","crv":"P-256","x":"%s","y":"%s"}
            ]}
            """.formatted(
            base64Url(fixedLength(ecKey.getW().getAffineX(), 32)),
            base64Url(fixedLength(ecKey.getW().getAffineY(), 32)));

        PublicKey found = JwksKeys.findKey(jwks, "key-2");

        assertEquals(kp.getPublic(), found);
    }

    @Test
    void usesTheOnlyKeyWhenNoKidRequested() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey rsaKey = (RSAPublicKey) kp.getPublic();
        String jwks = """
            {"keys": [{"kty":"RSA","n":"%s","e":"%s"}]}
            """.formatted(base64Url(rsaKey.getModulus().toByteArray()), base64Url(rsaKey.getPublicExponent().toByteArray()));

        PublicKey found = JwksKeys.findKey(jwks, null);

        assertEquals(kp.getPublic(), found);
    }

    @Test
    void throwsWhenKidNotFound() {
        String jwks = """
            {"keys": [{"kty":"RSA","kid":"other","n":"AQ","e":"AQ"}]}
            """;
        assertThrows(JwksKeys.JwksException.class, () -> JwksKeys.findKey(jwks, "missing"));
    }

    @Test
    void throwsWhenAmbiguousAndNoKidGiven() {
        String jwks = """
            {"keys": [
              {"kty":"RSA","kid":"a","n":"AQ","e":"AQ"},
              {"kty":"RSA","kid":"b","n":"AQ","e":"AQ"}
            ]}
            """;
        assertThrows(JwksKeys.JwksException.class, () -> JwksKeys.findKey(jwks, null));
    }

    @Test
    void rejectsUnsupportedKeyType() {
        String jwks = """
            {"keys": [{"kty":"oct","kid":"x","k":"AQ"}]}
            """;
        assertThrows(JwksKeys.JwksException.class, () -> JwksKeys.findKey(jwks, "x"));
    }

    @Test
    void rejectsMalformedJson() {
        assertThrows(JwksKeys.JwksException.class, () -> JwksKeys.findKey("not json", null));
    }

    @Test
    void rejectsMissingKeysArray() {
        assertThrows(JwksKeys.JwksException.class, () -> JwksKeys.findKey("{}", null));
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] fixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        // Strip a leading sign byte if present, then left-pad with zeros to the fixed length -
        // matches how a real JWKS encodes EC coordinates (RFC 7518 section 6.2.1.2/1.3).
        int start = (raw.length > length && raw[0] == 0) ? 1 : 0;
        byte[] trimmed = java.util.Arrays.copyOfRange(raw, start, raw.length);
        byte[] padded = new byte[length];
        System.arraycopy(trimmed, 0, padded, length - trimmed.length, trimmed.length);
        return padded;
    }
}
