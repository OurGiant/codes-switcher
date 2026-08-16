package com.ourgiant.crypt.crypto.jwt;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EcdsaSignatureFormatTest {

    @Test
    void derToRawThenRawToDerRoundTripsARealSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(kp.getPrivate());
        signer.update("test data".getBytes());
        byte[] originalDer = signer.sign();

        byte[] raw = EcdsaSignatureFormat.derToRaw(originalDer, 32);
        assertEquals(64, raw.length); // P-256: 32 bytes r + 32 bytes s

        byte[] reDer = EcdsaSignatureFormat.rawToDer(raw, 32);

        // The re-encoded DER may differ byte-for-byte from the original in edge cases (DER's
        // encoding is canonical, so it generally won't - but what actually matters is that the
        // JDK accepts the re-encoded signature as valid), not that the bytes are identical.
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(kp.getPublic());
        verifier.update("test data".getBytes());
        assertTrue(verifier.verify(reDer));
    }

    @Test
    void rawToDerProducesAValidSignatureAcrossManySamples() throws Exception {
        // ECDSA signatures are randomized (a fresh nonce each time), so r/s values vary in byte
        // length (leading zero or not) run to run - looping catches the sign-padding edge cases
        // a single lucky/unlucky sample could miss.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        for (int i = 0; i < 25; i++) {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(kp.getPrivate());
            signer.update(("sample " + i).getBytes());
            byte[] der = signer.sign();
            byte[] raw = EcdsaSignatureFormat.derToRaw(der, 32);
            byte[] reDer = EcdsaSignatureFormat.rawToDer(raw, 32);

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(kp.getPublic());
            verifier.update(("sample " + i).getBytes());
            assertTrue(verifier.verify(reDer), "sample " + i + " failed to verify after round-trip");
        }
    }

    @Test
    void rejectsWrongLengthRawSignature() {
        try {
            EcdsaSignatureFormat.rawToDer(new byte[10], 32);
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    void handlesValuesRequiringSignPaddingInBothDirections() {
        // A raw r/s value with the high bit set (e.g. 0xFF...) needs a 0x00 sign-padding byte
        // in DER form to stay a positive INTEGER - construct one directly rather than relying on
        // randomness to eventually produce this case.
        byte[] r = new byte[32];
        Arrays.fill(r, (byte) 0xFF);
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) 0x01);
        byte[] raw = new byte[64];
        System.arraycopy(r, 0, raw, 0, 32);
        System.arraycopy(s, 0, raw, 32, 32);

        byte[] der = EcdsaSignatureFormat.rawToDer(raw, 32);
        byte[] roundTripped = EcdsaSignatureFormat.derToRaw(der, 32);

        assertArrayEquals(raw, roundTripped);
    }
}
