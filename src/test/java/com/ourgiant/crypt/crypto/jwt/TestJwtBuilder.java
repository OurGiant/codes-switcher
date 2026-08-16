package com.ourgiant.crypt.crypto.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

/** Builds real, correctly-signed JWT strings for tests - not shipped in the main app. */
final class TestJwtBuilder {

    private TestJwtBuilder() {
    }

    static String header(String alg) {
        return "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}";
    }

    static String headerWithKid(String alg, String kid) {
        return "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
    }

    static String signingInput(String headerJson, String payloadJson) {
        return base64Url(headerJson) + "." + base64Url(payloadJson);
    }

    static String hmacSigned(String headerJson, String payloadJson, String alg, byte[] secret) throws Exception {
        String macAlg = switch (alg) {
            case "HS256" -> "HmacSHA256";
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> throw new IllegalArgumentException(alg);
        };
        String signingInput = signingInput(headerJson, payloadJson);
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(secret, macAlg));
        byte[] sig = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64UrlBytes(sig);
    }

    static String rsaSigned(String headerJson, String payloadJson, String alg, PrivateKey privateKey) throws Exception {
        String sigAlg = switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> throw new IllegalArgumentException(alg);
        };
        String signingInput = signingInput(headerJson, payloadJson);
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] sig = signature.sign();
        return signingInput + "." + base64UrlBytes(sig);
    }

    static String ecSigned(String headerJson, String payloadJson, String alg, PrivateKey privateKey, int fieldSizeBytes) throws Exception {
        String sigAlg = switch (alg) {
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            default -> throw new IllegalArgumentException(alg);
        };
        String signingInput = signingInput(headerJson, payloadJson);
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] derSig = signature.sign();
        byte[] rawSig = EcdsaSignatureFormat.derToRaw(derSig, fieldSizeBytes);
        return signingInput + "." + base64UrlBytes(rawSig);
    }

    static String payload(Map<String, Object> claims) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : claims.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            Object v = entry.getValue();
            if (v instanceof String s) {
                sb.append("\"").append(s).append("\"");
            } else {
                sb.append(v);
            }
        }
        return sb.append("}").toString();
    }

    private static String base64Url(String s) {
        return base64UrlBytes(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64UrlBytes(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
