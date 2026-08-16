package com.ourgiant.crypt.crypto.cert;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Generates real, self-signed X.509 test certificates via {@code keytool} (bundled with every
 * JDK, located next to the running JVM via java.home - not relying on PATH) rather than
 * committing binary certificate fixtures or hand-rolling ASN.1 DER, matching this project
 * family's "fixtures as code" convention (see doc-scrubber's FixtureBuilder). The JDK has no
 * public API for *creating* a signed certificate (only parsing one), so keytool is the
 * dependency-free way to get a real cert for tests.
 */
final class CertFixtures {

    private static final String KEYTOOL = System.getProperty("java.home") + File.separator + "bin"
        + File.separator + "keytool";

    private CertFixtures() {
    }

    static X509Certificate selfSigned(Path tempDir, String alias, String dname, String keyAlg,
            String groupNameOrKeySize, int validityDays) throws Exception {
        return selfSigned(tempDir, alias, dname, keyAlg, groupNameOrKeySize, validityDays, null);
    }

    /** @param startDateOffset e.g. "-400d" to backdate the cert's start (used for an already-expired fixture); null for "now". */
    static X509Certificate selfSigned(Path tempDir, String alias, String dname, String keyAlg,
            String groupNameOrKeySize, int validityDays, String startDateOffset) throws Exception {
        File keystoreFile = tempDir.resolve(alias + ".p12").toFile();

        var command = new java.util.ArrayList<String>(java.util.List.of(
            KEYTOOL, "-genkeypair",
            "-alias", alias,
            "-keyalg", keyAlg,
            "-sigalg", "EC".equals(keyAlg) ? "SHA256withECDSA" : "SHA256withRSA",
            "-dname", dname,
            "-validity", String.valueOf(validityDays),
            "-keystore", keystoreFile.getAbsolutePath(),
            "-storepass", "changeit",
            "-keypass", "changeit",
            "-noprompt"));
        command.add("EC".equals(keyAlg) ? "-groupname" : "-keysize");
        command.add(groupNameOrKeySize);
        if (startDateOffset != null) {
            command.add("-startdate");
            command.add(startDateOffset);
        }

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        boolean finished = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
        if (!finished || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed (exit=" + (finished ? process.exitValue() : "timeout")
                + "):\n" + output);
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(keystoreFile)) {
            keyStore.load(in, "changeit".toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Builds a genuine two-certificate chain: a self-signed CA, and a leaf certificate actually
     * signed by that CA (via keytool's -certreq/-gencert CSR flow) - for testing
     * ChainValidator's positive path against a real signature relationship, not just rejecting
     * mismatched certs.
     */
    static X509Certificate[] caSignedLeafChain(Path tempDir) throws Exception {
        File caKeystore = tempDir.resolve("ca.p12").toFile();
        File leafKeystore = tempDir.resolve("leaf.p12").toFile();
        File csrFile = tempDir.resolve("leaf.csr").toFile();
        File signedCertFile = tempDir.resolve("leaf-signed.cer").toFile();

        run("-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048",
            "-sigalg", "SHA256withRSA", "-dname", "CN=Test CA", "-validity", "3650",
            "-keystore", caKeystore.getAbsolutePath(), "-storepass", "changeit", "-keypass", "changeit", "-noprompt");

        run("-genkeypair", "-alias", "leaf", "-keyalg", "RSA", "-keysize", "2048",
            "-sigalg", "SHA256withRSA", "-dname", "CN=leaf.example.com", "-validity", "3650",
            "-keystore", leafKeystore.getAbsolutePath(), "-storepass", "changeit", "-keypass", "changeit", "-noprompt");

        run("-certreq", "-alias", "leaf", "-keystore", leafKeystore.getAbsolutePath(),
            "-storepass", "changeit", "-file", csrFile.getAbsolutePath());

        run("-gencert", "-alias", "ca", "-keystore", caKeystore.getAbsolutePath(), "-storepass", "changeit",
            "-infile", csrFile.getAbsolutePath(), "-outfile", signedCertFile.getAbsolutePath(),
            "-validity", "3650");

        KeyStore caKeyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(caKeystore)) {
            caKeyStore.load(in, "changeit".toCharArray());
        }
        X509Certificate caCert = (X509Certificate) caKeyStore.getCertificate("ca");

        var factory = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate leafCert;
        try (FileInputStream in = new FileInputStream(signedCertFile)) {
            leafCert = (X509Certificate) factory.generateCertificate(in);
        }

        return new X509Certificate[]{leafCert, caCert};
    }

    private static void run(String... args) throws Exception {
        var command = new java.util.ArrayList<String>();
        command.add(KEYTOOL);
        command.addAll(java.util.List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        boolean finished = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
        if (!finished || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed (exit=" + (finished ? process.exitValue() : "timeout")
                + "):\n" + output);
        }
    }
}
