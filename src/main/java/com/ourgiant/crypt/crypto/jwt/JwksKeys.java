package com.ourgiant.crypt.crypto.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * Parses a JWKS ("JSON Web Key Set") document - the response from a {@code jwks_uri} - into
 * PublicKeys, hand-rolled against RFC 7517/7518's RSA and EC key field layouts rather than
 * pulling in a full JOSE library, per the tracking issue's dependency note. Deliberately limited
 * to the JWA algorithms this tool actually verifies (RS* / ES*) - no support for other key types
 * (oct, OKP) since there's nothing here that would use them.
 */
public final class JwksKeys {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // JWA curve name (as it appears in a JWK's "crv" field) -> JDK's standard curve name.
    private static final Map<String, String> JDK_CURVE_NAMES = Map.of(
        "P-256", "secp256r1",
        "P-384", "secp384r1",
        "P-521", "secp521r1");

    private JwksKeys() {
    }

    public static final class JwksException extends RuntimeException {
        public JwksException(String message) {
            super(message);
        }

        public JwksException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * @param keyId the token's "kid" header value; if null and the key set has exactly one key,
     *              that key is used (matches common JWKS practice for single-key issuers).
     */
    public static PublicKey findKey(String jwksJson, String keyId) {
        JsonNode root;
        try {
            root = MAPPER.readTree(jwksJson);
        } catch (Exception e) {
            throw new JwksException("JWKS response is not valid JSON: " + e.getMessage(), e);
        }

        JsonNode keys = root.path("keys");
        if (!keys.isArray() || keys.isEmpty()) {
            throw new JwksException("JWKS response has no \"keys\" array");
        }

        JsonNode match = null;
        if (keyId != null) {
            for (JsonNode key : keys) {
                if (keyId.equals(key.path("kid").asText(null))) {
                    match = key;
                    break;
                }
            }
            if (match == null) {
                throw new JwksException("No key in the JWKS matches the token's kid \"" + keyId + "\"");
            }
        } else if (keys.size() == 1) {
            match = keys.get(0);
        } else {
            throw new JwksException(
                "Token has no \"kid\" and the JWKS has " + keys.size() + " keys - can't tell which one to use");
        }

        return toPublicKey(match);
    }

    private static PublicKey toPublicKey(JsonNode jwk) {
        String kty = jwk.path("kty").asText(null);
        if ("RSA".equals(kty)) {
            return toRsaPublicKey(jwk);
        }
        if ("EC".equals(kty)) {
            return toEcPublicKey(jwk);
        }
        throw new JwksException("Unsupported JWK key type \"" + kty + "\" - only RSA and EC are supported");
    }

    private static PublicKey toRsaPublicKey(JsonNode jwk) {
        BigInteger modulus = unsignedBigIntFromBase64Url(jwk, "n");
        BigInteger exponent = unsignedBigIntFromBase64Url(jwk, "e");
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new JwksException("Failed to build RSA public key from JWK: " + e.getMessage(), e);
        }
    }

    private static PublicKey toEcPublicKey(JsonNode jwk) {
        String crv = jwk.path("crv").asText(null);
        String jdkCurveName = JDK_CURVE_NAMES.get(crv);
        if (jdkCurveName == null) {
            throw new JwksException("Unsupported EC curve \"" + crv + "\" - only P-256/P-384/P-521 are supported");
        }
        BigInteger x = unsignedBigIntFromBase64Url(jwk, "x");
        BigInteger y = unsignedBigIntFromBase64Url(jwk, "y");
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(jdkCurveName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(x, y), ecSpec);
            return KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (Exception e) {
            throw new JwksException("Failed to build EC public key from JWK: " + e.getMessage(), e);
        }
    }

    private static BigInteger unsignedBigIntFromBase64Url(JsonNode jwk, String field) {
        String value = jwk.path(field).asText(null);
        if (value == null) {
            throw new JwksException("JWK is missing required field \"" + field + "\"");
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(padBase64Url(value));
            return new BigInteger(1, bytes); // unsigned - a JWK coordinate is never negative
        } catch (IllegalArgumentException e) {
            throw new JwksException("JWK field \"" + field + "\" is not valid Base64URL: " + e.getMessage(), e);
        }
    }

    private static String padBase64Url(String value) {
        int remainder = value.length() % 4;
        return remainder == 0 ? value : value + "=".repeat(4 - remainder);
    }
}
