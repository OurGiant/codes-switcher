package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacVerifierTest {

    @Test
    void verifiesAGenuinelySignedHs256Token() throws Exception {
        byte[] secret = "correct-secret".getBytes(StandardCharsets.UTF_8);
        String header = TestJwtBuilder.header("HS256");
        String payload = TestJwtBuilder.payload(Map.of("sub", "alice"));
        String jwt = TestJwtBuilder.hmacSigned(header, payload, "HS256", secret);
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertTrue(HmacVerifier.verify(parsed.signingInput(), parsed.signature(), "HS256", secret));
    }

    @Test
    void rejectsAWrongSecret() throws Exception {
        String header = TestJwtBuilder.header("HS256");
        String payload = TestJwtBuilder.payload(Map.of("sub", "alice"));
        String jwt = TestJwtBuilder.hmacSigned(header, payload, "HS256", "right-secret".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertFalse(HmacVerifier.verify(parsed.signingInput(), parsed.signature(), "HS256", "wrong-secret".getBytes()));
    }

    @Test
    void rejectsATamperedPayload() throws Exception {
        String header = TestJwtBuilder.header("HS256");
        byte[] secret = "secret".getBytes();
        String jwt = TestJwtBuilder.hmacSigned(header, TestJwtBuilder.payload(Map.of("role", "user")), "HS256", secret);
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        // signingInput is base64url-encoded, so a string-replace on plaintext substrings like
        // "user" wouldn't reliably land on (or even exist in) the encoded bytes - flip a byte
        // directly instead, which is guaranteed to actually change what was signed.
        byte[] tamperedInput = parsed.signingInput().clone();
        tamperedInput[0] ^= 0x01;

        assertFalse(HmacVerifier.verify(tamperedInput, parsed.signature(), "HS256", secret));
    }

    @Test
    void supportsAllThreeHmacAlgorithms() {
        assertTrue(HmacVerifier.supports("HS256"));
        assertTrue(HmacVerifier.supports("HS384"));
        assertTrue(HmacVerifier.supports("HS512"));
    }

    @Test
    void rejectsNonHmacAlgorithms() {
        assertFalse(HmacVerifier.supports("RS256"));
        assertFalse(HmacVerifier.supports("ES256"));
        assertThrows(IllegalArgumentException.class, () -> HmacVerifier.verify(new byte[0], new byte[0], "RS256", new byte[0]));
    }

    @Test
    void hs384And512Work() throws Exception {
        for (String alg : new String[]{"HS384", "HS512"}) {
            byte[] secret = "secret".getBytes();
            String header = TestJwtBuilder.header(alg);
            String jwt = TestJwtBuilder.hmacSigned(header, TestJwtBuilder.payload(Map.of("sub", "x")), alg, secret);
            JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

            assertTrue(HmacVerifier.verify(parsed.signingInput(), parsed.signature(), alg, secret));
        }
    }
}
