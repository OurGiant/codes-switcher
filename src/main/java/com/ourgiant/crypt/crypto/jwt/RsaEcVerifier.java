package com.ourgiant.crypt.crypto.jwt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

/**
 * Verifies RS256/384/512 (RSA) and ES256/384/512 (ECDSA) signed JWTs against a public key.
 * ECDSA needs a format conversion first - see EcdsaSignatureFormat's javadoc for why.
 */
public final class RsaEcVerifier {

    private static final Map<String, String> RSA_SIGNATURE_ALGORITHMS = Map.of(
        "RS256", "SHA256withRSA",
        "RS384", "SHA384withRSA",
        "RS512", "SHA512withRSA");

    private static final Map<String, String> EC_SIGNATURE_ALGORITHMS = Map.of(
        "ES256", "SHA256withECDSA",
        "ES384", "SHA384withECDSA",
        "ES512", "SHA512withECDSA");

    // JWA-specified fixed field size per curve (RFC 7518 section 3.4).
    private static final Map<String, Integer> EC_FIELD_SIZE_BYTES = Map.of(
        "ES256", 32,
        "ES384", 48,
        "ES512", 66);

    private RsaEcVerifier() {
    }

    public static boolean supportsRsa(String alg) {
        return RSA_SIGNATURE_ALGORITHMS.containsKey(alg);
    }

    public static boolean supportsEc(String alg) {
        return EC_SIGNATURE_ALGORITHMS.containsKey(alg);
    }

    public static boolean verify(byte[] signingInput, byte[] signature, String alg, PublicKey publicKey) {
        if (supportsRsa(alg)) {
            return verifyWithSignatureAlgorithm(signingInput, signature, RSA_SIGNATURE_ALGORITHMS.get(alg), publicKey);
        }
        if (supportsEc(alg)) {
            byte[] derSignature = EcdsaSignatureFormat.rawToDer(signature, EC_FIELD_SIZE_BYTES.get(alg));
            return verifyWithSignatureAlgorithm(signingInput, derSignature, EC_SIGNATURE_ALGORITHMS.get(alg), publicKey);
        }
        throw new IllegalArgumentException("Not an RSA or EC algorithm: " + alg);
    }

    private static boolean verifyWithSignatureAlgorithm(byte[] signingInput, byte[] signatureBytes,
            String signatureAlgorithm, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(signingInput);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(
                "This public key doesn't match the token's algorithm (" + signatureAlgorithm
                    + ") - wrong key type or size", e);
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new IllegalStateException("Signature verification failed: " + e.getMessage(), e);
        }
    }
}
