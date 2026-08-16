package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtVerificationTest {

    @Test
    void verifiesAGenuineHmacToken() throws Exception {
        byte[] secret = "secret".getBytes();
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("sub", "alice")), "HS256", secret);

        JwtVerification.Outcome outcome = JwtVerification.verifyHmac(jwt, secret);

        assertTrue(outcome.algorithmMatchesKeyType());
        assertTrue(outcome.signatureValid());
        assertNull(outcome.error());
    }

    @Test
    void rejectsHmacTokenWithWrongSecret() throws Exception {
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("sub", "alice")), "HS256", "right".getBytes());

        JwtVerification.Outcome outcome = JwtVerification.verifyHmac(jwt, "wrong".getBytes());

        assertTrue(outcome.algorithmMatchesKeyType());
        assertFalse(outcome.signatureValid());
    }

    @Test
    void verifiesAGenuineRsaToken() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String jwt = TestJwtBuilder.rsaSigned(TestJwtBuilder.header("RS256"),
            TestJwtBuilder.payload(Map.of("sub", "alice")), "RS256", kp.getPrivate());

        JwtVerification.Outcome outcome = JwtVerification.verifyWithPublicKey(jwt, kp.getPublic());

        assertTrue(outcome.algorithmMatchesKeyType());
        assertTrue(outcome.signatureValid());
    }

    /**
     * The core defense this feature exists for (RFC 8725 3.1/3.2 algorithm confusion): a token
     * claims HS256, but the caller supplied an RSA public key (expecting RS256). A naive
     * implementation that reinterprets the RSA public key's bytes as an HMAC secret would
     * "verify" successfully if an attacker crafted exactly that token - a well-known real-world
     * JWT library vulnerability class. This must be refused outright, not attempted.
     */
    @Test
    void refusesToVerifyHmacTokenAgainstAnRsaPublicKey() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        // Attacker signs with the RSA public key's own encoded bytes as if it were an HMAC secret.
        byte[] publicKeyBytesAsSecret = kp.getPublic().getEncoded();
        String forgedToken = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("sub", "attacker", "admin", true)), "HS256", publicKeyBytesAsSecret);

        JwtVerification.Outcome outcome = JwtVerification.verifyWithPublicKey(forgedToken, kp.getPublic());

        assertFalse(outcome.algorithmMatchesKeyType());
        assertNull(outcome.signatureValid(), "signature verification must never even run for a mismatched alg/key");
        assertTrue(outcome.error().contains("HS256"));
    }

    @Test
    void refusesToVerifyRsaTokenAgainstAnHmacSecret() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String jwt = TestJwtBuilder.rsaSigned(TestJwtBuilder.header("RS256"),
            TestJwtBuilder.payload(Map.of("sub", "x")), "RS256", kp.getPrivate());

        JwtVerification.Outcome outcome = JwtVerification.verifyHmac(jwt, "some-secret".getBytes());

        assertFalse(outcome.algorithmMatchesKeyType());
        assertNull(outcome.signatureValid());
    }

    @Test
    void refusesToVerifyEcTokenAgainstAnRsaPublicKey() throws Exception {
        var kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair ecKp = kpg.generateKeyPair();
        KeyPair rsaKp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        String jwt = TestJwtBuilder.ecSigned(TestJwtBuilder.header("ES256"),
            TestJwtBuilder.payload(Map.of("sub", "x")), "ES256", ecKp.getPrivate(), 32);

        JwtVerification.Outcome outcome = JwtVerification.verifyWithPublicKey(jwt, rsaKp.getPublic());

        assertFalse(outcome.algorithmMatchesKeyType());
        assertNull(outcome.signatureValid());
    }

    @Test
    void malformedTokenProducesAnErrorOutcomeNotAnException() {
        JwtVerification.Outcome outcome = JwtVerification.verifyHmac("not.a.jwt", "secret".getBytes());

        assertNull(outcome.token());
        assertFalse(outcome.algorithmMatchesKeyType());
        assertNull(outcome.signatureValid());
        assertTrue(outcome.error() != null);
    }

    // --- Time-validity checks (using the package-private Clock-injectable overload) ---

    @Test
    void reportsValidWhenWithinExpiryAndNotBeforeWindow() throws Exception {
        long now = 1_000_000L;
        Clock fixedClock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("exp", now + 3600, "nbf", now - 3600)), "HS256", "s".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        var result = JwtVerification.timeStatus(parsed, fixedClock);

        assertEquals(JwtVerification.TimeStatus.VALID, result.status());
    }

    @Test
    void reportsExpiredWhenPastExp() throws Exception {
        long now = 1_000_000L;
        Clock fixedClock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("exp", now - 1)), "HS256", "s".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        var result = JwtVerification.timeStatus(parsed, fixedClock);

        assertEquals(JwtVerification.TimeStatus.EXPIRED, result.status());
    }

    @Test
    void reportsNotYetValidWhenBeforeNbf() throws Exception {
        long now = 1_000_000L;
        Clock fixedClock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("nbf", now + 3600)), "HS256", "s".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        var result = JwtVerification.timeStatus(parsed, fixedClock);

        assertEquals(JwtVerification.TimeStatus.NOT_YET_VALID, result.status());
    }

    @Test
    void reportsNoTimeClaimsWhenNeitherExpNorNbfPresent() throws Exception {
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("sub", "x")), "HS256", "s".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        var result = JwtVerification.timeStatus(parsed, Clock.systemUTC());

        assertEquals(JwtVerification.TimeStatus.NO_TIME_CLAIMS, result.status());
    }

    @Test
    void exactlyAtExpiryIsConsideredExpired() throws Exception {
        long now = 1_000_000L;
        Clock fixedClock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
        String jwt = TestJwtBuilder.hmacSigned(TestJwtBuilder.header("HS256"),
            TestJwtBuilder.payload(Map.of("exp", now)), "HS256", "s".getBytes());
        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        var result = JwtVerification.timeStatus(parsed, fixedClock);

        assertEquals(JwtVerification.TimeStatus.EXPIRED, result.status());
    }
}
