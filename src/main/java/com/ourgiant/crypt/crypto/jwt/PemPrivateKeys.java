package com.ourgiant.crypt.crypto.jwt;

import com.ourgiant.crypt.crypto.jwt.PemPublicKeys.InvalidPemException;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Parses a pasted PEM private key: PKCS#8 ("BEGIN PRIVATE KEY", RSA or EC) or
 * PKCS#1 ("BEGIN RSA PRIVATE KEY"). Encrypted keys are rejected with a hint.
 */
public final class PemPrivateKeys {

    private PemPrivateKeys() {
    }

    // AlgorithmIdentifier for rsaEncryption: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
    private static final byte[] RSA_ALG_ID = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };

    public static PrivateKey parse(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new InvalidPemException("No private key provided");
        }
        String text = pem.strip();
        if (text.contains("ENCRYPTED")) {
            throw new InvalidPemException("Encrypted private keys aren't supported. Decrypt first, e.g. "
                    + "`openssl pkcs8 -topk8 -nocrypt -in key.pem`");
        }
        if (text.contains("BEGIN EC PRIVATE KEY")) {
            throw new InvalidPemException("SEC1 \"EC PRIVATE KEY\" isn't supported. Convert to PKCS#8 with "
                    + "`openssl pkcs8 -topk8 -nocrypt -in key.pem`");
        }
        if (text.contains("BEGIN PUBLIC KEY") || text.contains("BEGIN CERTIFICATE")) {
            throw new InvalidPemException("That's a public key or certificate; signing needs the private key");
        }
        byte[] der = body(text);
        if (text.contains("BEGIN RSA PRIVATE KEY")) {
            der = wrapPkcs1(der);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        for (String alg : new String[]{"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException ignored) {
                // try the next key type
            }
        }
        throw new InvalidPemException("Not a recognized RSA or EC private key (PKCS#8)");
    }

    private static byte[] body(String pem) {
        StringBuilder b64 = new StringBuilder();
        for (String line : pem.split("\\r?\\n")) {
            String t = line.strip();
            if (!t.isEmpty() && !t.startsWith("-----") && !t.contains(":")) {
                b64.append(t);
            }
        }
        if (b64.isEmpty()) {
            throw new InvalidPemException("No PEM body found between BEGIN/END markers");
        }
        try {
            return Base64.getDecoder().decode(b64.toString());
        } catch (IllegalArgumentException e) {
            throw new InvalidPemException("PEM body is not valid Base64: " + e.getMessage(), e);
        }
    }

    /** PKCS#8 PrivateKeyInfo ::= SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING pkcs1 }. */
    static byte[] wrapPkcs1(byte[] pkcs1) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.writeBytes(new byte[]{0x02, 0x01, 0x00});
        inner.writeBytes(RSA_ALG_ID);
        inner.write(0x04);
        writeLength(inner, pkcs1.length);
        inner.writeBytes(pkcs1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, inner.size());
        out.writeBytes(inner.toByteArray());
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        } else if (len < 0x10000) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
    }
}
