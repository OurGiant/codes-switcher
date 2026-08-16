package com.ourgiant.crypt.crypto.cert;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509InspectorTest {

    @Test
    void inspectsAStrongSelfSignedRsaCertificate(@TempDir Path tempDir) throws Exception {
        X509Certificate cert = CertFixtures.selfSigned(
            tempDir, "strong-rsa", "CN=strong.example.com", "RSA", "2048", 3650);

        X509Inspector.Inspection inspection = X509Inspector.inspect(cert);

        assertEquals("CN=strong.example.com", inspection.subject());
        assertEquals("CN=strong.example.com", inspection.issuer());
        assertTrue(inspection.selfSigned());
        assertTrue(inspection.selfSignatureValid());
        assertFalse(inspection.expired());
        assertFalse(inspection.notYetValid());
        assertFalse(inspection.weakKey());
        assertEquals("RSA", inspection.keyAlgorithm());
        assertEquals(2048, inspection.keySizeBits());
        // SHA-256 fingerprint: 32 bytes, colon-separated hex = 32*2 + 31 = 95 characters.
        assertEquals(95, inspection.sha256Fingerprint().length());
    }

    @Test
    void flagsAWeakRsaKey(@TempDir Path tempDir) throws Exception {
        X509Certificate cert = CertFixtures.selfSigned(
            tempDir, "weak-rsa", "CN=weak.example.com", "RSA", "1024", 3650);

        X509Inspector.Inspection inspection = X509Inspector.inspect(cert);

        assertTrue(inspection.weakKey());
        assertEquals(1024, inspection.keySizeBits());
        assertTrue(inspection.weakKeyDetail().contains("1024"));
    }

    @Test
    void flagsAnExpiredCertificate(@TempDir Path tempDir) throws Exception {
        // Backdated 400 days, valid for only 30 days - definitely expired by "now".
        X509Certificate cert = CertFixtures.selfSigned(
            tempDir, "expired", "CN=expired.example.com", "RSA", "2048", 30, "-400d");

        X509Inspector.Inspection inspection = X509Inspector.inspect(cert);

        assertTrue(inspection.expired());
        assertFalse(inspection.notYetValid());
    }

    @Test
    void inspectsAnEcCertificate(@TempDir Path tempDir) throws Exception {
        X509Certificate cert = CertFixtures.selfSigned(
            tempDir, "ec-cert", "CN=ec.example.com", "EC", "secp256r1", 3650);

        X509Inspector.Inspection inspection = X509Inspector.inspect(cert);

        assertEquals("EC", inspection.keyAlgorithm());
        assertEquals(256, inspection.keySizeBits());
        assertFalse(inspection.weakKey()); // 256 >= 224-bit EC minimum
    }

    @Test
    void parsesAPemCertificateFromCertificateFactoryEncoding(@TempDir Path tempDir) throws Exception {
        X509Certificate cert = CertFixtures.selfSigned(
            tempDir, "pem-roundtrip", "CN=pem.example.com", "RSA", "2048", 3650);

        String pem = "-----BEGIN CERTIFICATE-----\n"
            + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
            + "\n-----END CERTIFICATE-----\n";

        X509Certificate parsed = X509Inspector.parseSingle(pem);

        assertEquals(cert.getSubjectX500Principal(), parsed.getSubjectX500Principal());
    }

    @Test
    void rejectsGarbageInput() {
        assertThrows(X509Inspector.CertParseException.class, () -> X509Inspector.parseSingle("not a certificate"));
        assertThrows(X509Inspector.CertParseException.class, () -> X509Inspector.parseSingle(""));
    }

    @Test
    void parseSingleRejectsMultipleCertificates(@TempDir Path tempDir) throws Exception {
        X509Certificate[] chain = CertFixtures.caSignedLeafChain(tempDir);
        String bundle = toPem(chain[0]) + toPem(chain[1]);

        assertThrows(X509Inspector.CertParseException.class, () -> X509Inspector.parseSingle(bundle));

        List<X509Certificate> parsed = X509Inspector.parseChain(bundle);
        assertEquals(2, parsed.size());
    }

    @Test
    void toPemChainRoundTripsThroughParseChain(@TempDir Path tempDir) throws Exception {
        X509Certificate[] chain = CertFixtures.caSignedLeafChain(tempDir);

        String pem = X509Inspector.toPemChain(List.of(chain[0], chain[1]));
        List<X509Certificate> parsed = X509Inspector.parseChain(pem);

        assertEquals(2, parsed.size());
        assertEquals(chain[0], parsed.get(0));
        assertEquals(chain[1], parsed.get(1));
    }

    private static String toPem(X509Certificate cert) {
        return X509Inspector.toPem(cert);
    }
}
