package com.ourgiant.crypt.crypto.cert;

import com.ourgiant.crypt.crypto.asn1.Der;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** PKCS#12 / JKS keystores and PKCS#10 CSRs, all produced by the JDK's own keytool. */
class CertFormatsTest {

    @TempDir
    Path dir;

    private Path keystore(String type, String alias, String keyAlg, String size) throws Exception {
        Path ks = dir.resolve(alias + "." + type.toLowerCase());
        CertFixtures.run("-genkeypair", "-alias", alias, "-keyalg", keyAlg,
                "EC".equals(keyAlg) ? "-groupname" : "-keysize", size,
                "-dname", "CN=" + alias + ".example.com, O=Test",
                "-ext", "SAN=dns:" + alias + ".example.com,dns:www." + alias + ".example.com,ip:10.0.0.7",
                "-validity", "30", "-storetype", type, "-keystore", ks.toString(),
                "-storepass", "changeit", "-keypass", "changeit", "-noprompt");
        return ks;
    }

    @ParameterizedTest
    @CsvSource({"PKCS12, RSA, 2048", "JKS, EC, secp256r1"})
    void readsKeystores(String type, String keyAlg, String size) throws Exception {
        Path ks = keystore(type, "site", keyAlg, size);
        CertFixtures.run("-importcert", "-alias", "zz-trusted", "-file", exportCert(ks, type, "site").toString(),
                "-storetype", type, "-keystore", ks.toString(), "-storepass", "changeit", "-noprompt");
        byte[] data = Files.readAllBytes(ks);
        assertEquals(type, KeyStoreReader.detectType(data));

        List<KeyStoreReader.Entry> entries = KeyStoreReader.read(data, "changeit".toCharArray());
        assertEquals(2, entries.size());
        assertEquals("site", entries.get(0).alias());
        assertEquals(KeyStoreReader.Kind.PRIVATE_KEY, entries.get(0).kind());
        X509Certificate cert = entries.get(0).chain().get(0);
        assertTrue(cert.getSubjectX500Principal().getName().contains("CN=site.example.com"));
        assertEquals(KeyStoreReader.Kind.TRUSTED_CERT, entries.get(1).kind());
    }

    @ParameterizedTest
    @CsvSource({"PKCS12", "JKS"})
    void wrongPasswordIsReported(String type) throws Exception {
        byte[] data = Files.readAllBytes(keystore(type, "pw", "RSA", "2048"));
        assertThrows(KeyStoreReader.WrongPasswordException.class,
                () -> KeyStoreReader.read(data, "nope".toCharArray()));
    }

    @Test
    void notAKeystore() {
        assertNull(KeyStoreReader.detectType("hello".getBytes()));
    }

    @Test
    void derCertificateParses() throws Exception {
        Path ks = keystore("PKCS12", "der", "RSA", "2048");
        Path der = exportCert(ks, "PKCS12", "der");
        X509Certificate pemParsed = X509Inspector.parseSingle(Files.readString(exportPem(ks, "der")));
        X509Certificate derParsed = X509Inspector.parseDer(Files.readAllBytes(der)).get(0);
        assertEquals(pemParsed, derParsed);
    }

    @ParameterizedTest
    @CsvSource({"RSA, 2048, SHA256withRSA, RSA 2048 bits", "EC, secp384r1, SHA384withECDSA, EC 384 bits"})
    void parsesKeytoolCsr(String keyAlg, String size, String sigAlg, String keyDesc) throws Exception {
        Path ks = keystore("PKCS12", "csr", keyAlg, size);
        Path csr = dir.resolve("req.csr");
        CertFixtures.run("-certreq", "-alias", "csr", "-sigalg", sigAlg, "-keystore", ks.toString(),
                "-storepass", "changeit", "-file", csr.toString(),
                "-ext", "SAN=dns:csr.example.com,ip:192.168.1.5,email:admin@example.com");
        String pem = Files.readString(csr);
        assertTrue(CsrParser.looksLikeCsr(pem));

        CsrParser.Csr parsed = CsrParser.parsePem(pem);
        assertEquals("CN=csr.example.com,O=Test", parsed.subject());
        assertEquals(keyDesc, parsed.keyDescription());
        assertEquals(sigAlg, parsed.signatureAlgorithm());
        assertEquals(Boolean.TRUE, parsed.signatureValid());
        assertEquals(List.of("DNS:csr.example.com", "IP:192.168.1.5", "email:admin@example.com"), parsed.requestedSans());
    }

    @Test
    void tamperedCsrSignatureFails() throws Exception {
        Path ks = keystore("PKCS12", "tamper", "RSA", "2048");
        Path csr = dir.resolve("t.csr");
        CertFixtures.run("-certreq", "-alias", "tamper", "-keystore", ks.toString(), "-storepass", "changeit",
                "-file", csr.toString());
        String pem = Files.readString(csr);
        String b64 = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);
        der[der.length - 5] ^= 1; // inside the signature
        assertEquals(Boolean.FALSE, CsrParser.parse(der).signatureValid());
    }

    @Test
    void malformedDerIsRejected() {
        assertThrows(X509Inspector.CertParseException.class, () -> CsrParser.parse(new byte[]{0x30, 0x05, 0x02}));
        assertThrows(X509Inspector.CertParseException.class, () -> CsrParser.parse(new byte[]{0x30, (byte) 0x80, 0, 0}));
        assertThrows(X509Inspector.CertParseException.class, () -> CsrParser.parsePem("no csr here"));
        assertThrows(Der.DerException.class, () -> Der.parse(new byte[]{0x02, 0x01, 0x00, 0x00}));
    }

    @Test
    void derOidDecoding() {
        Der.Node n = Der.parse(new byte[]{0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b});
        assertEquals("1.2.840.113549.1.1.11", n.oid());
    }

    private Path exportCert(Path ks, String type, String alias) throws Exception {
        Path out = dir.resolve(alias + "-" + System.nanoTime() + ".der");
        CertFixtures.run("-exportcert", "-alias", alias, "-storetype", type, "-keystore", ks.toString(),
                "-storepass", "changeit", "-file", out.toString());
        return out;
    }

    private Path exportPem(Path ks, String alias) throws Exception {
        Path out = dir.resolve(alias + ".pem");
        CertFixtures.run("-exportcert", "-rfc", "-alias", alias, "-keystore", ks.toString(),
                "-storepass", "changeit", "-file", out.toString());
        return out;
    }
}
