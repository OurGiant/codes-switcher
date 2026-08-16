package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PemPublicKeysTest {

    @Test
    void parsesAPemEncodedRsaPublicKey() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String pem = toPem(kp.getPublic());

        PublicKey parsed = PemPublicKeys.parse(pem);

        assertEquals(kp.getPublic(), parsed);
    }

    @Test
    void parsesAPemEncodedEcPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        String pem = toPem(kp.getPublic());

        PublicKey parsed = PemPublicKeys.parse(pem);

        assertEquals(kp.getPublic(), parsed);
    }

    @Test
    void toleratesSurroundingWhitespaceAndBlankLines() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String pem = "\n\n  " + toPem(kp.getPublic()) + "\n  \n";

        PublicKey parsed = PemPublicKeys.parse(pem);

        assertEquals(kp.getPublic(), parsed);
    }

    @Test
    void rejectsGarbageInput() {
        assertThrows(PemPublicKeys.InvalidPemException.class, () -> PemPublicKeys.parse("not a key"));
        assertThrows(PemPublicKeys.InvalidPemException.class, () -> PemPublicKeys.parse(""));
        assertThrows(PemPublicKeys.InvalidPemException.class, () -> PemPublicKeys.parse(null));
    }

    @Test
    void rejectsNonBase64Body() {
        String badPem = "-----BEGIN PUBLIC KEY-----\nnot!valid!base64!\n-----END PUBLIC KEY-----";
        assertThrows(PemPublicKeys.InvalidPemException.class, () -> PemPublicKeys.parse(badPem));
    }

    private static String toPem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }
}
