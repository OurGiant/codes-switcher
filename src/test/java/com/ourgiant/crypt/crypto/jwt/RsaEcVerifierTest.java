package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaEcVerifierTest {

    @Test
    void verifiesAGenuinelySignedRs256Token() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String header = TestJwtBuilder.header("RS256");
        String payload = TestJwtBuilder.payload(Map.of("sub", "alice"));
        String jwt = TestJwtBuilder.rsaSigned(header, payload, "RS256", kp.getPrivate());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertTrue(RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), "RS256", kp.getPublic()));
    }

    @Test
    void rejectsRsaSignatureFromAWrongKey() throws Exception {
        KeyPair signingKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyPair differentKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String jwt = TestJwtBuilder.rsaSigned(TestJwtBuilder.header("RS256"),
            TestJwtBuilder.payload(Map.of("sub", "x")), "RS256", signingKey.getPrivate());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertFalse(RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), "RS256", differentKey.getPublic()));
    }

    @Test
    void verifiesAGenuinelySignedEs256TokenRoundTrippingRawDerConversion() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        String header = TestJwtBuilder.header("ES256");
        String payload = TestJwtBuilder.payload(Map.of("sub", "alice"));
        // TestJwtBuilder signs with the JDK (producing DER), then converts to raw JWS format via
        // EcdsaSignatureFormat.derToRaw - exercising the exact inverse of what RsaEcVerifier
        // does internally (rawToDer), so this test genuinely round-trips both directions.
        String jwt = TestJwtBuilder.ecSigned(header, payload, "ES256", kp.getPrivate(), 32);
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertTrue(RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), "ES256", kp.getPublic()));
    }

    @Test
    void es384And512Work() throws Exception {
        record Curve(String alg, String jdkName, int fieldSize) {
        }
        for (Curve c : new Curve[]{new Curve("ES384", "secp384r1", 48), new Curve("ES512", "secp521r1", 66)}) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(c.jdkName()));
            KeyPair kp = kpg.generateKeyPair();

            String jwt = TestJwtBuilder.ecSigned(TestJwtBuilder.header(c.alg()),
                TestJwtBuilder.payload(Map.of("sub", "x")), c.alg(), kp.getPrivate(), c.fieldSize());
            JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

            assertTrue(RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), c.alg(), kp.getPublic()));
        }
    }

    @Test
    void rejectsEcSignatureFromAWrongKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair signingKey = kpg.generateKeyPair();
        KeyPair differentKey = kpg.generateKeyPair();

        String jwt = TestJwtBuilder.ecSigned(TestJwtBuilder.header("ES256"),
            TestJwtBuilder.payload(Map.of("sub", "x")), "ES256", signingKey.getPrivate(), 32);
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertFalse(RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), "ES256", differentKey.getPublic()));
    }

    @Test
    void rejectsUnsupportedAlgorithm() {
        assertFalse(RsaEcVerifier.supportsRsa("HS256"));
        assertFalse(RsaEcVerifier.supportsEc("HS256"));
        assertThrows(IllegalArgumentException.class,
            () -> RsaEcVerifier.verify(new byte[0], new byte[0], "HS256", null));
    }
}
