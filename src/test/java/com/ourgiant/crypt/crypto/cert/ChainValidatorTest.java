package com.ourgiant.crypt.crypto.cert;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainValidatorTest {

    @Test
    void genuineCaSignedLeafChainValidatesSuccessfully(@TempDir Path tempDir) throws Exception {
        X509Certificate[] chain = CertFixtures.caSignedLeafChain(tempDir); // [leaf, ca]

        ChainValidator.ChainResult result = ChainValidator.validate(List.of(chain[0], chain[1]));

        assertTrue(result.allValid());
        assertEquals(1, result.links().size());
        assertTrue(result.links().get(0).signatureValid());
    }

    @Test
    void unrelatedCertificatesFailChainValidation(@TempDir Path tempDir) throws Exception {
        X509Certificate certA = CertFixtures.selfSigned(tempDir, "a", "CN=a.example.com", "RSA", "2048", 3650);
        X509Certificate certB = CertFixtures.selfSigned(tempDir, "b", "CN=b.example.com", "RSA", "2048", 3650);

        // certA was NOT signed by certB's key - two independent self-signed certs.
        ChainValidator.ChainResult result = ChainValidator.validate(List.of(certA, certB));

        assertFalse(result.allValid());
        assertFalse(result.links().get(0).signatureValid());
    }

    @Test
    void singleCertificateHasNoLinksAndIsTriviallyValid(@TempDir Path tempDir) throws Exception {
        X509Certificate cert = CertFixtures.selfSigned(tempDir, "solo", "CN=solo.example.com", "RSA", "2048", 3650);

        ChainValidator.ChainResult result = ChainValidator.validate(List.of(cert));

        assertTrue(result.links().isEmpty());
        assertTrue(result.allValid());
    }
}
