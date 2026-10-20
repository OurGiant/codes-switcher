package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtSignerTest {

    private static final String PAYLOAD = "{\"sub\":\"1234\",\"name\":\"Ada\"}";
    private static final byte[] SECRET = "a-string-secret-at-least-256-bits-long".getBytes(StandardCharsets.UTF_8);

    /**
     * Turns a PKCS#8 RSA key into the traditional PKCS#1 "BEGIN RSA PRIVATE KEY" PEM that
     * `openssl genrsa -traditional` writes, by unwrapping the inner OCTET STRING.
     */
    private static String pkcs1Pem(KeyPair kp) {
        byte[] p8 = kp.getPrivate().getEncoded();
        int i = 1 + lengthBytes(p8, 1); // outer SEQUENCE tag + length
        i += 3;                          // INTEGER 0
        i += 2 + (p8[i + 1] & 0xff);     // AlgorithmIdentifier SEQUENCE
        if (p8[i] != 0x04) {
            throw new IllegalStateException("expected OCTET STRING");
        }
        int lenOfLen = lengthBytes(p8, i + 1);
        int len = 0;
        for (int k = 1; k < lenOfLen; k++) {
            len = (len << 8) | (p8[i + 1 + k] & 0xff);
        }
        int bodyStart = i + 1 + lenOfLen;
        byte[] pkcs1 = java.util.Arrays.copyOfRange(p8, bodyStart, bodyStart + len);
        return "-----BEGIN RSA PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs1)
                + "\n-----END RSA PRIVATE KEY-----\n";
    }

    /** Number of bytes in the DER length field starting at {@code idx} (long form only). */
    private static int lengthBytes(byte[] der, int idx) {
        int first = der[idx] & 0xff;
        return first < 0x80 ? 1 : 1 + (first & 0x7f);
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static String pkcs8Pem(KeyPair kp) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    @ParameterizedTest
    @ValueSource(strings = {"HS256", "HS384", "HS512"})
    void hmacTokensVerify(String alg) throws Exception {
        String jwt = JwtSigner.signHmac("{}", PAYLOAD, alg, SECRET);
        JwtVerification.Outcome o = JwtVerification.verifyHmac(jwt, SECRET);
        assertNull(o.error());
        assertEquals(Boolean.TRUE, o.signatureValid());
        assertEquals(alg, o.token().algorithm());
        assertEquals(Boolean.FALSE, JwtVerification.verifyHmac(jwt, "other".getBytes()).signatureValid());
    }

    @Test
    void knownHs256Token() throws Exception {
        // Same header/payload/secret as the jwt.io default example, compact JSON.
        String jwt = JwtSigner.signHmac("{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}",
                "HS256", SECRET);
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
                + "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30", jwt);
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512"})
    void rsaTokensVerify(String alg) throws Exception {
        KeyPair kp = rsa();
        String jwt = JwtSigner.signWithKey("{\"kid\":\"k1\"}", PAYLOAD, alg,
                PemPrivateKeys.parse(pkcs8Pem(kp)));
        JwtVerification.Outcome o = JwtVerification.verifyWithPublicKey(jwt, kp.getPublic());
        assertEquals(Boolean.TRUE, o.signatureValid(), o.error());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256:secp256r1", "ES384:secp384r1", "ES512:secp521r1"})
    void ecTokensVerify(String spec) throws Exception {
        String[] p = spec.split(":");
        KeyPair kp = ec(p[1]);
        String jwt = JwtSigner.signWithKey("{}", PAYLOAD, p[0], PemPrivateKeys.parse(pkcs8Pem(kp)));
        JwtVerification.Outcome o = JwtVerification.verifyWithPublicKey(jwt, kp.getPublic());
        assertEquals(Boolean.TRUE, o.signatureValid(), o.error());
    }

    @Test
    void pkcs1RsaKeyWorks() throws Exception {
        KeyPair kp = rsa();
        String pem = pkcs1Pem(kp);
        assertTrue(pem.startsWith("-----BEGIN RSA PRIVATE KEY-----"));
        String jwt = JwtSigner.signWithKey("{}", PAYLOAD, "RS256", PemPrivateKeys.parse(pem));
        JwtVerification.Outcome o = JwtVerification.verifyWithPublicKey(jwt, kp.getPublic());
        assertEquals(Boolean.TRUE, o.signatureValid(), o.error());
    }

    @Test
    void headerAlgIsAlwaysOverwritten() throws Exception {
        String jwt = JwtSigner.signHmac("{\"alg\":\"none\",\"kid\":\"x\"}", PAYLOAD, "HS256", SECRET);
        String header = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]), StandardCharsets.UTF_8);
        assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"x\"}", header);
    }

    @Test
    void noneIsNotAnOption() {
        assertFalse(JwtSigner.ALGORITHMS.contains("none"));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signHmac("{}", PAYLOAD, "none", SECRET));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signWithKey("{}", PAYLOAD, "none", null));
    }

    @Test
    void keyTypeAndCurveMustMatch() throws Exception {
        KeyPair r = rsa();
        KeyPair p256 = ec("secp256r1");
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signWithKey("{}", PAYLOAD, "ES256", r.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signWithKey("{}", PAYLOAD, "RS256", p256.getPrivate()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> JwtSigner.signWithKey("{}", PAYLOAD, "ES384", p256.getPrivate()));
        assertTrue(e.getMessage().contains("P-384"));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signWithKey("{}", PAYLOAD, "HS256", r.getPrivate()));
    }

    @Test
    void badJsonRejected() {
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signHmac("{}", "{not json", "HS256", SECRET));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signHmac("[]", PAYLOAD, "HS256", SECRET));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signHmac("{}", "42", "HS256", SECRET));
        assertThrows(IllegalArgumentException.class, () -> JwtSigner.signHmac("{}", PAYLOAD, "HS256", new byte[0]));
    }

    @Test
    void timeClaimsHelper() throws Exception {
        String withTimes = JwtSigner.withTimeClaims(PAYLOAD, Instant.ofEpochSecond(1_000), 3600);
        assertTrue(withTimes.contains("\"iat\" : 1000"));
        assertTrue(withTimes.contains("\"exp\" : 4600"));
        assertTrue(withTimes.contains("\"sub\" : \"1234\""));
        String jwt = JwtSigner.signHmac("{}", JwtSigner.withTimeClaims(PAYLOAD, Instant.now(), 60), "HS256", SECRET);
        assertEquals(JwtVerification.TimeStatus.VALID, JwtVerification.verifyHmac(jwt, SECRET).timeStatus());
    }

    @Test
    void pemErrorsAreHelpful() {
        assertThrows(PemPublicKeys.InvalidPemException.class, () -> PemPrivateKeys.parse(""));
        assertTrue(assertThrows(PemPublicKeys.InvalidPemException.class,
                () -> PemPrivateKeys.parse("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----"))
                .getMessage().contains("openssl pkcs8"));
        assertTrue(assertThrows(PemPublicKeys.InvalidPemException.class,
                () -> PemPrivateKeys.parse("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"))
                .getMessage().contains("Encrypted"));
        assertThrows(PemPublicKeys.InvalidPemException.class,
                () -> PemPrivateKeys.parse("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"));
        assertThrows(PemPublicKeys.InvalidPemException.class,
                () -> PemPrivateKeys.parse("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"));
    }
}
