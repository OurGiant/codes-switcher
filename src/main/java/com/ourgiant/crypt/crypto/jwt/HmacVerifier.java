package com.ourgiant.crypt.crypto.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Map;

/** Verifies HS256/HS384/HS512-signed JWTs against a user-supplied shared secret. */
public final class HmacVerifier {

    private static final Map<String, String> MAC_ALGORITHMS = Map.of(
        "HS256", "HmacSHA256",
        "HS384", "HmacSHA384",
        "HS512", "HmacSHA512");

    private HmacVerifier() {
    }

    public static boolean supports(String alg) {
        return MAC_ALGORITHMS.containsKey(alg);
    }

    /**
     * @param secret the shared secret as UTF-8 bytes (the common case for a pasted passphrase)
     */
    public static boolean verify(byte[] signingInput, byte[] signature, String alg, byte[] secret) {
        String macAlgorithm = MAC_ALGORITHMS.get(alg);
        if (macAlgorithm == null) {
            throw new IllegalArgumentException("Not an HMAC algorithm: " + alg);
        }
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(secret, macAlgorithm));
            byte[] expected = mac.doFinal(signingInput);
            // MessageDigest.isEqual is constant-time - a naive Arrays.equals would let an
            // attacker measure signature bytes one at a time via response-timing.
            return MessageDigest.isEqual(expected, signature);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC verification failed: " + e.getMessage(), e);
        }
    }
}
