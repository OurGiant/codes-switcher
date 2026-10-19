package com.ourgiant.crypt.crypto.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Creates signed JWTs (JWS compact form). The header's "alg" is always set from the chosen
 * algorithm so it can't disagree with the signature, and "none" is never produced.
 */
public final class JwtSigner {

    public static final List<String> ALGORITHMS = List.of(
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512");

    private static final ObjectMapper JSON = new ObjectMapper();

    private JwtSigner() {
    }

    public static boolean isHmac(String alg) {
        return alg.startsWith("HS");
    }

    /** Signs with an HMAC secret (HS256/384/512). */
    public static String signHmac(String headerJson, String payloadJson, String alg, byte[] secret)
            throws GeneralSecurityException {
        if (!isHmac(alg) || !ALGORITHMS.contains(alg)) {
            throw new IllegalArgumentException(alg + " is not an HMAC algorithm");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("An HMAC secret is required");
        }
        String macAlg = "HmacSHA" + alg.substring(2);
        String input = signingInput(headerJson, payloadJson, alg);
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(secret, macAlg));
        return input + "." + b64(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
    }

    /** Signs with an RSA (RS*) or EC (ES*) private key. */
    public static String signWithKey(String headerJson, String payloadJson, String alg, PrivateKey key)
            throws GeneralSecurityException {
        if (!ALGORITHMS.contains(alg) || isHmac(alg)) {
            throw new IllegalArgumentException(alg + " needs an HMAC secret, not a private key");
        }
        String bits = alg.substring(2);
        String input = signingInput(headerJson, payloadJson, alg);
        byte[] data = input.getBytes(StandardCharsets.US_ASCII);
        byte[] sig;
        if (alg.startsWith("RS")) {
            if (!(key instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException(alg + " needs an RSA private key");
            }
            Signature s = Signature.getInstance("SHA" + bits + "withRSA");
            s.initSign(key);
            s.update(data);
            sig = s.sign();
        } else {
            if (!(key instanceof ECPrivateKey ec)) {
                throw new IllegalArgumentException(alg + " needs an EC private key");
            }
            int fieldBits = ec.getParams().getCurve().getField().getFieldSize();
            int expectedBits = switch (alg) {
                case "ES256" -> 256;
                case "ES384" -> 384;
                default -> 521;
            };
            if (fieldBits != expectedBits) {
                throw new IllegalArgumentException(alg + " needs a P-" + expectedBits + " key, but this key is "
                        + fieldBits + "-bit (RFC 7518 §3.4)");
            }
            Signature s = Signature.getInstance("SHA" + bits + "withECDSA");
            s.initSign(key);
            s.update(data);
            sig = EcdsaSignatureFormat.derToRaw(s.sign(), (fieldBits + 7) / 8);
        }
        return input + "." + b64(sig);
    }

    /** Returns the payload JSON with "iat" set to now and, if {@code expSeconds > 0}, "exp" set to now + that. */
    public static String withTimeClaims(String payloadJson, Instant now, long expSeconds) {
        ObjectNode payload = parseObject(payloadJson, "Payload");
        payload.put("iat", now.getEpochSecond());
        if (expSeconds > 0) {
            payload.put("exp", now.getEpochSecond() + expSeconds);
        }
        return pretty(payload);
    }

    static String signingInput(String headerJson, String payloadJson, String alg) {
        ObjectNode header = parseObject(headerJson.isBlank() ? "{}" : headerJson, "Header");
        // Rebuild so "alg" comes first and always matches the signature.
        ObjectNode fixed = JSON.createObjectNode();
        fixed.put("alg", alg);
        if (!header.has("typ")) {
            fixed.put("typ", "JWT");
        }
        header.fields().forEachRemaining(e -> {
            if (!e.getKey().equals("alg")) {
                fixed.set(e.getKey(), e.getValue());
            }
        });
        ObjectNode payload = parseObject(payloadJson, "Payload");
        return b64(compact(fixed)) + "." + b64(compact(payload));
    }

    private static ObjectNode parseObject(String json, String what) {
        JsonNode node;
        try {
            node = JSON.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(what + " is not valid JSON: " + e.getOriginalMessage());
        }
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException(what + " must be a JSON object");
        }
        return (ObjectNode) node;
    }

    private static byte[] compact(JsonNode node) {
        try {
            return JSON.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String pretty(JsonNode node) {
        try {
            return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
