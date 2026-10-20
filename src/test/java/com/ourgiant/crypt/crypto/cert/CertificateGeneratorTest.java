package com.ourgiant.crypt.crypto.cert;

import com.ourgiant.crypt.crypto.asn1.DerWriter;
import com.ourgiant.crypt.crypto.cert.CertificateGenerator.CertRequest;
import com.ourgiant.crypt.crypto.cert.CertificateGenerator.KeyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertificateGeneratorTest {

    private static final CertRequest SERVER = new CertRequest("app.example.com", "Acme, Inc.",
            List.of("app.example.com", "*.app.example.com", "10.1.2.3", "ip:::1", "email:ops@example.com"), 397, false);

    // RSA 3072/4096 are slow to generate; the cert code path is the same as RSA 2048.
    @ParameterizedTest
    @EnumSource(value = KeyType.class, names = {"RSA_3072", "RSA_4096"}, mode = EnumSource.Mode.EXCLUDE)
    void serverCertificateIsValid(KeyType type) throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(type);
        X509Certificate cert = CertificateGenerator.selfSigned(kp, SERVER);

        cert.verify(kp.getPublic());
        cert.checkValidity();
        assertEquals(3, cert.getVersion());
        assertEquals("CN=app.example.com,O=Acme\\, Inc.", cert.getSubjectX500Principal().getName());
        assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
        assertEquals(-1, cert.getBasicConstraints(), "not a CA");
        assertTrue(cert.getCriticalExtensionOIDs().containsAll(List.of("2.5.29.19", "2.5.29.15")));
        assertTrue(cert.getKeyUsage()[0], "digitalSignature");
        assertEquals(type.isRsa(), cert.getKeyUsage()[2], "keyEncipherment only for RSA");
        assertFalse(cert.getKeyUsage()[5], "no keyCertSign");
        assertEquals(List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"), cert.getExtendedKeyUsage());
        assertNotNull(cert.getExtensionValue("2.5.29.14"), "subjectKeyIdentifier");
        assertTrue(cert.getSerialNumber().signum() > 0);

        List<String> sans = cert.getSubjectAlternativeNames().stream().map(l -> l.get(0) + "=" + l.get(1)).toList();
        assertEquals(List.of("2=app.example.com", "2=*.app.example.com", "7=10.1.2.3", "7=0:0:0:0:0:0:0:1",
                "1=ops@example.com"), sans);

        X509Inspector.Inspection inspection = X509Inspector.inspect(cert);
        assertTrue(inspection.selfSigned());
        assertTrue(inspection.selfSignatureValid());
        assertFalse(inspection.weakKey());
    }

    @Test
    void caCertificate() throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(KeyType.EC_P384);
        X509Certificate ca = CertificateGenerator.selfSigned(kp, new CertRequest("Test Root CA", null, List.of(), 3650, true));
        assertEquals(Integer.MAX_VALUE, ca.getBasicConstraints());
        assertTrue(ca.getKeyUsage()[5] && ca.getKeyUsage()[6], "keyCertSign + cRLSign");
        assertNull(ca.getExtendedKeyUsage());
        assertNull(ca.getSubjectAlternativeNames());
        assertEquals("SHA384withECDSA", ca.getSigAlgName());
    }

    @Test
    void cnIsUsedAsSanWhenNoneGiven() throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(KeyType.EC_P256);
        X509Certificate c = CertificateGenerator.selfSigned(kp, new CertRequest("localhost", null, List.of(), 30, false));
        assertEquals("localhost", c.getSubjectAlternativeNames().iterator().next().get(1));
    }

    @Test
    void farFutureExpiryUsesGeneralizedTime() throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(KeyType.ED25519);
        X509Certificate c = CertificateGenerator.selfSigned(kp, new CertRequest("long.example", null, List.of(), 36500, false));
        assertTrue(c.getNotAfter().toInstant().atZone(java.time.ZoneOffset.UTC).getYear() > 2100);
    }

    @Test
    void keyPairSizesAndPem() throws Exception {
        KeyPair rsa = CertificateGenerator.generateKeyPair(KeyType.RSA_3072);
        assertEquals(3072, ((java.security.interfaces.RSAPublicKey) rsa.getPublic()).getModulus().bitLength());
        String pem = CertificateGenerator.privateKeyPem(rsa.getPrivate());
        assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", ""));
        assertEquals(rsa.getPrivate(), KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der)));
        assertTrue(CertificateGenerator.publicKeyPem(rsa.getPublic()).startsWith("-----BEGIN PUBLIC KEY-----"));
    }

    @Test
    void pkcs12RoundTrip() throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(KeyType.EC_P256);
        X509Certificate cert = CertificateGenerator.selfSigned(kp, SERVER);
        byte[] p12 = CertificateGenerator.pkcs12(kp, cert, "app", "pw".toCharArray());
        List<KeyStoreReader.Entry> entries = KeyStoreReader.read(p12, "pw".toCharArray());
        assertEquals(1, entries.size());
        assertEquals("app", entries.get(0).alias());
        assertEquals(KeyStoreReader.Kind.PRIVATE_KEY, entries.get(0).kind());
        assertEquals(cert, entries.get(0).chain().get(0));
        assertThrows(IllegalArgumentException.class, () -> CertificateGenerator.pkcs12(kp, cert, "a", new char[0]));
    }

    @Test
    void validatesRequest() throws Exception {
        KeyPair kp = CertificateGenerator.generateKeyPair(KeyType.EC_P256);
        assertThrows(IllegalArgumentException.class,
                () -> CertificateGenerator.selfSigned(kp, new CertRequest(" ", null, List.of(), 30, false)));
        assertThrows(IllegalArgumentException.class,
                () -> CertificateGenerator.selfSigned(kp, new CertRequest("x", null, List.of(), 0, false)));
        assertThrows(IllegalArgumentException.class,
                () -> CertificateGenerator.selfSigned(kp, new CertRequest("x", null, List.of("bad host!"), 30, false)));
        assertThrows(IllegalArgumentException.class,
                () -> CertificateGenerator.selfSigned(kp, new CertRequest("x", null, List.of("ip:300.1.1.1"), 30, false)));
    }

    @Test
    void derWriterNamedBitsTrimsTrailingZeros() {
        // digitalSignature + keyEncipherment = 1010 0000 -> 5 unused bits
        assertArrayEquals(new byte[]{0x03, 0x02, 0x05, (byte) 0xA0}, DerWriter.namedBits(0, 2));
        // digitalSignature + keyCertSign + cRLSign = 1000 0110 -> 1 unused bit
        assertArrayEquals(new byte[]{0x03, 0x02, 0x01, (byte) 0x86}, DerWriter.namedBits(0, 5, 6));
        // bit 8 spills into a second byte
        assertArrayEquals(new byte[]{0x03, 0x03, 0x07, (byte) 0x80, (byte) 0x80}, DerWriter.namedBits(0, 8));
    }

    @Test
    void derWriterOidAndLengthsRoundTripThroughReader() {
        String oid = "1.2.840.113549.1.9.14";
        assertEquals(oid, com.ourgiant.crypt.crypto.asn1.Der.parse(DerWriter.oid(oid)).oid());
        byte[] big = new byte[70000];
        assertEquals(70000, com.ourgiant.crypt.crypto.asn1.Der.parse(DerWriter.octetString(big)).length());
    }
}
