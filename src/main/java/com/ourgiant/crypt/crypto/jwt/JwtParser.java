package com.ourgiant.crypt.crypto.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Pure parsing of the three-part JWT structure (header.payload.signature) into its decoded
 * pieces - no signature verification here, see HmacVerifier/RsaEcVerifier for that. Explicitly
 * rejects {@code alg: none} at parse time: an unsigned token has no signature to verify, and
 * accepting it silently is exactly the "none algorithm" bypass every JWT security advisory
 * warns about.
 */
public final class JwtParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwtParser() {
    }

    public static final class MalformedJwtException extends RuntimeException {
        public MalformedJwtException(String message) {
            super(message);
        }
    }

    public record ParsedJwt(
        String headerJson,
        String payloadJson,
        String algorithm,
        String keyId,
        byte[] signingInput,   // "header.payload" as ASCII bytes - what the signature covers
        byte[] signature,
        Long exp,
        Long nbf,
        Long iat) {
    }

    public static ParsedJwt parse(String jwt) {
        if (jwt == null) {
            throw new MalformedJwtException("JWT is empty");
        }
        String trimmed = jwt.trim();
        String[] parts = trimmed.split("\\.");
        if (parts.length != 3) {
            throw new MalformedJwtException(
                "Invalid JWT format. Expected 3 parts separated by dots, got " + parts.length);
        }

        String headerJson = decodePart(parts[0], "header");
        String payloadJson = decodePart(parts[1], "payload");

        JsonNode header = readJson(headerJson, "header");
        JsonNode payload = readJson(payloadJson, "payload");

        String alg = header.path("alg").asText(null);
        if (alg == null || alg.isBlank()) {
            throw new MalformedJwtException("JWT header is missing \"alg\"");
        }
        if ("none".equalsIgnoreCase(alg)) {
            throw new MalformedJwtException(
                "Refusing to process a token with alg=\"none\" - this token is unsigned by design "
                    + "and cannot be verified. Accepting it would be exactly the classic "
                    + "\"none algorithm\" bypass.");
        }

        String kid = header.path("kid").asText(null);
        Long exp = payload.hasNonNull("exp") ? payload.path("exp").asLong() : null;
        Long nbf = payload.hasNonNull("nbf") ? payload.path("nbf").asLong() : null;
        Long iat = payload.hasNonNull("iat") ? payload.path("iat").asLong() : null;

        String signingInputStr = parts[0] + "." + parts[1];
        byte[] signingInput = signingInputStr.getBytes(StandardCharsets.US_ASCII);
        byte[] signature = base64UrlDecode(parts[2], "signature");

        return new ParsedJwt(headerJson, payloadJson, alg, kid, signingInput, signature, exp, nbf, iat);
    }

    private static String decodePart(String part, String name) {
        byte[] decoded = base64UrlDecode(part, name);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static byte[] base64UrlDecode(String part, String name) {
        try {
            return Base64.getUrlDecoder().decode(padBase64Url(part));
        } catch (IllegalArgumentException e) {
            throw new MalformedJwtException("JWT " + name + " is not valid Base64URL: " + e.getMessage());
        }
    }

    private static String padBase64Url(String value) {
        int remainder = value.length() % 4;
        if (remainder == 0) {
            return value;
        }
        return value + "=".repeat(4 - remainder);
    }

    private static JsonNode readJson(String json, String name) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new MalformedJwtException("JWT " + name + " is not valid JSON: " + e.getMessage());
        }
    }
}
