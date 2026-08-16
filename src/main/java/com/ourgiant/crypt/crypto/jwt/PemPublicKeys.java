package com.ourgiant.crypt.crypto.jwt;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Parses a pasted PEM-encoded public key ("-----BEGIN PUBLIC KEY-----...") into a PublicKey. */
public final class PemPublicKeys {

    private PemPublicKeys() {
    }

    public static final class InvalidPemException extends RuntimeException {
        public InvalidPemException(String message) {
            super(message);
        }

        public InvalidPemException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static PublicKey parse(String pem) {
        byte[] der = decodePemBody(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);

        // The DER bytes embed an AlgorithmIdentifier OID; KeyFactory.generatePublic rejects the
        // spec if it doesn't match the requested key type, so trying RSA then EC (the two JWA
        // key types this tool verifies) is a simple, correct way to detect which one it is
        // without hand-parsing the ASN.1 ourselves.
        InvalidKeySpecException lastFailure;
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            lastFailure = e;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA KeyFactory unavailable", e);
        }
        try {
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidPemException(
                "Not a recognized RSA or EC public key (SubjectPublicKeyInfo): " + lastFailure.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC KeyFactory unavailable", e);
        }
    }

    private static byte[] decodePemBody(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new InvalidPemException("No key provided");
        }
        StringBuilder base64Body = new StringBuilder();
        for (String line : pem.strip().split("\\r?\\n")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("-----")) {
                continue;
            }
            base64Body.append(trimmed);
        }
        if (base64Body.isEmpty()) {
            throw new InvalidPemException("No PEM body found between BEGIN/END markers");
        }
        try {
            return Base64.getDecoder().decode(base64Body.toString());
        } catch (IllegalArgumentException e) {
            throw new InvalidPemException("PEM body is not valid Base64: " + e.getMessage(), e);
        }
    }
}
