package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtParserTest {

    @Test
    void parsesHeaderPayloadAlgAndClaims() throws Exception {
        String header = TestJwtBuilder.header("HS256");
        String payload = TestJwtBuilder.payload(Map.of("sub", "alice", "exp", 9999999999L, "nbf", 1L));
        String jwt = TestJwtBuilder.hmacSigned(header, payload, "HS256", "secret".getBytes());

        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertEquals("HS256", parsed.algorithm());
        assertTrue(parsed.payloadJson().contains("alice"));
        assertEquals(9999999999L, parsed.exp());
        assertEquals(1L, parsed.nbf());
        assertNull(parsed.keyId());
    }

    @Test
    void parsesKeyId() throws Exception {
        String header = TestJwtBuilder.headerWithKid("RS256", "key-42");
        String payload = TestJwtBuilder.payload(Map.of("sub", "bob"));
        // A well-formed (if not cryptographically meaningful) base64url signature segment - this
        // test only cares about kid parsing, not signature validity.
        String jwt = TestJwtBuilder.signingInput(header, payload) + "." + fakeBase64UrlSignature();

        JwtParser.ParsedJwt parsed = JwtParser.parse(jwt);

        assertEquals("key-42", parsed.keyId());
    }

    @Test
    void rejectsAlgNoneRegardlessOfCase() {
        for (String noneVariant : new String[]{"none", "None", "NONE"}) {
            String header = TestJwtBuilder.header(noneVariant);
            String payload = TestJwtBuilder.payload(Map.of("sub", "attacker"));
            // A real (if empty-signed) third segment - "alg: none" tokens are conventionally
            // sent with an empty signature part, which still needs to be *present* (an empty
            // string is valid, 3-part-producing input) for the parser to even reach the alg
            // check, unlike a bare trailing "." (which Java's String.split() collapses away,
            // leaving only 2 parts and triggering the wrong rejection reason).
            String jwt = TestJwtBuilder.signingInput(header, payload) + ".x";

            JwtParser.MalformedJwtException ex = assertThrows(
                JwtParser.MalformedJwtException.class, () -> JwtParser.parse(jwt));
            assertTrue(ex.getMessage().toLowerCase().contains("none"));
        }
    }

    private static String fakeBase64UrlSignature() {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{1, 2, 3, 4});
    }

    @Test
    void rejectsWrongNumberOfParts() {
        assertThrows(JwtParser.MalformedJwtException.class, () -> JwtParser.parse("only.two"));
        assertThrows(JwtParser.MalformedJwtException.class, () -> JwtParser.parse("a.b.c.d"));
    }

    @Test
    void rejectsInvalidBase64() {
        assertThrows(JwtParser.MalformedJwtException.class, () -> JwtParser.parse("!!!.!!!.!!!"));
    }

    @Test
    void rejectsNonJsonPayload() {
        String header = TestJwtBuilder.header("HS256");
        String notJson = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("not json".getBytes());
        String jwt = base64UrlOf(header) + "." + notJson + ".sig";

        assertThrows(JwtParser.MalformedJwtException.class, () -> JwtParser.parse(jwt));
    }

    @Test
    void rejectsMissingAlg() {
        String header = "{\"typ\":\"JWT\"}";
        String payload = TestJwtBuilder.payload(Map.of("sub", "x"));
        String jwt = TestJwtBuilder.signingInput(header, payload) + ".sig";

        assertThrows(JwtParser.MalformedJwtException.class, () -> JwtParser.parse(jwt));
    }

    private static String base64UrlOf(String s) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes());
    }
}
