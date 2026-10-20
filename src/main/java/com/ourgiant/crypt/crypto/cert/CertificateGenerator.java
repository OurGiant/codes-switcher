package com.ourgiant.crypt.crypto.cert;

import com.ourgiant.crypt.crypto.asn1.Der;
import com.ourgiant.crypt.crypto.asn1.DerWriter;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/** Generates key pairs and self-signed X.509 v3 certificates, and exports them as PEM or PKCS#12. */
public final class CertificateGenerator {

    public enum KeyType {
        RSA_2048("RSA 2048"), RSA_3072("RSA 3072"), RSA_4096("RSA 4096"),
        EC_P256("EC P-256"), EC_P384("EC P-384"), ED25519("Ed25519");

        private final String label;

        KeyType(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }

        public boolean isRsa() {
            return name().startsWith("RSA");
        }
    }

    /** What to put in the certificate. {@code sans} entries are host names, IP addresses or "email:..." values. */
    public record CertRequest(String commonName, String organization, List<String> sans, int validityDays, boolean ca) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private CertificateGenerator() {
    }

    public static KeyPair generateKeyPair(KeyType type) throws GeneralSecurityException {
        KeyPairGenerator g;
        switch (type) {
            case RSA_2048, RSA_3072, RSA_4096 -> {
                g = KeyPairGenerator.getInstance("RSA");
                g.initialize(new RSAKeyGenParameterSpec(Integer.parseInt(type.name().substring(4)),
                        RSAKeyGenParameterSpec.F4), RANDOM);
            }
            case EC_P256, EC_P384 -> {
                g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec(type == KeyType.EC_P256 ? "secp256r1" : "secp384r1"), RANDOM);
            }
            case ED25519 -> g = KeyPairGenerator.getInstance("Ed25519");
            default -> throw new IllegalStateException();
        }
        return g.generateKeyPair();
    }

    public static X509Certificate selfSigned(KeyPair keys, CertRequest req) throws GeneralSecurityException {
        if (req.commonName() == null || req.commonName().isBlank()) {
            throw new IllegalArgumentException("A common name (CN) is required");
        }
        if (req.validityDays() < 1 || req.validityDays() > 36500) {
            throw new IllegalArgumentException("Validity must be between 1 and 36500 days");
        }
        X500Principal name = principal(req.commonName(), req.organization());
        String sigAlg = signatureAlgorithm(keys.getPublic());
        byte[] algId = algorithmIdentifier(keys.getPublic());

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        byte[] serial = new byte[16];
        RANDOM.nextBytes(serial);
        serial[0] &= 0x7f;   // keep it positive
        serial[0] |= 0x40;   // and 16 bytes long

        byte[] tbs = DerWriter.sequence(
                DerWriter.explicit(0, DerWriter.integer(2)),            // v3
                DerWriter.integer(new BigInteger(1, serial)),
                algId,
                name.getEncoded(),
                DerWriter.sequence(DerWriter.time(now.minusMinutes(5)), DerWriter.time(now.plusDays(req.validityDays()))),
                name.getEncoded(),
                keys.getPublic().getEncoded(),
                DerWriter.explicit(3, extensions(keys.getPublic(), req)));

        Signature s = Signature.getInstance(sigAlg);
        s.initSign(keys.getPrivate());
        s.update(tbs);
        byte[] cert = DerWriter.sequence(tbs, algId, DerWriter.bitString(s.sign()));

        X509Certificate x = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(cert));
        x.verify(keys.getPublic());
        return x;
    }

    private static byte[] extensions(PublicKey key, CertRequest req) throws GeneralSecurityException {
        List<byte[]> exts = new ArrayList<>();
        // basicConstraints: critical; cA=TRUE only for a CA certificate
        exts.add(extension("2.5.29.19", true,
                req.ca() ? DerWriter.sequence(DerWriter.bool(true)) : DerWriter.sequence()));
        // keyUsage: critical
        List<Integer> usage = new ArrayList<>(List.of(0)); // digitalSignature
        if (key.getAlgorithm().equals("RSA")) {
            usage.add(2); // keyEncipherment
        }
        if (req.ca()) {
            usage.add(5); // keyCertSign
            usage.add(6); // cRLSign
        }
        exts.add(extension("2.5.29.15", true, DerWriter.namedBits(usage.stream().mapToInt(Integer::intValue).toArray())));
        if (!req.ca()) {
            // extKeyUsage: serverAuth, clientAuth
            exts.add(extension("2.5.29.37", false,
                    DerWriter.sequence(DerWriter.oid("1.3.6.1.5.5.7.3.1"), DerWriter.oid("1.3.6.1.5.5.7.3.2"))));
        }
        List<String> sans = new ArrayList<>(req.sans() == null ? List.of() : req.sans());
        if (sans.isEmpty() && !req.ca() && !req.commonName().contains(" ")) {
            sans.add(req.commonName().strip()); // modern clients ignore CN and need a SAN
        }
        if (!sans.isEmpty()) {
            exts.add(extension("2.5.29.17", false, generalNames(sans)));
        }
        // subjectKeyIdentifier: SHA-1 of the subjectPublicKey bits (RFC 5280 §4.2.1.2 method 1)
        byte[] keyBits = Der.parse(key.getEncoded()).child(1).bitString();
        exts.add(extension("2.5.29.14", false,
                DerWriter.octetString(MessageDigest.getInstance("SHA-1").digest(keyBits))));
        return DerWriter.sequence(exts.toArray(byte[][]::new));
    }

    private static byte[] extension(String oid, boolean critical, byte[] value) {
        return critical
                ? DerWriter.sequence(DerWriter.oid(oid), DerWriter.bool(true), DerWriter.octetString(value))
                : DerWriter.sequence(DerWriter.oid(oid), DerWriter.octetString(value));
    }

    static byte[] generalNames(List<String> sans) {
        List<byte[]> names = new ArrayList<>();
        for (String raw : sans) {
            String s = raw.strip();
            if (s.isEmpty()) {
                continue;
            }
            String lower = s.toLowerCase();
            if (lower.startsWith("email:")) {
                names.add(DerWriter.implicitPrimitive(1, s.substring(6).strip().getBytes(StandardCharsets.US_ASCII)));
            } else if (lower.startsWith("ip:") || IPV4.matcher(s).matches() || s.contains(":")) {
                String ip = lower.startsWith("ip:") ? s.substring(3).strip() : s;
                try {
                    names.add(DerWriter.implicitPrimitive(7, InetAddress.ofLiteral(ip).getAddress()));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Not a valid IP address: " + ip);
                }
            } else {
                String host = lower.startsWith("dns:") ? s.substring(4).strip() : s;
                if (!host.matches("(\\*\\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*")) {
                    throw new IllegalArgumentException("Not a valid host name: " + host);
                }
                names.add(DerWriter.implicitPrimitive(2, host.getBytes(StandardCharsets.US_ASCII)));
            }
        }
        return DerWriter.sequence(names.toArray(byte[][]::new));
    }

    private static X500Principal principal(String cn, String org) {
        StringBuilder dn = new StringBuilder("CN=").append(escape(cn.strip()));
        if (org != null && !org.isBlank()) {
            dn.append(", O=").append(escape(org.strip()));
        }
        return new X500Principal(dn.toString());
    }

    private static String escape(String v) {
        return v.replaceAll("([,+\"\\\\<>;=#])", "\\\\$1");
    }

    private static String signatureAlgorithm(PublicKey key) {
        return switch (key.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize() > 256
                    ? "SHA384withECDSA" : "SHA256withECDSA";
            case "Ed25519", "EdDSA" -> "Ed25519";
            default -> throw new IllegalArgumentException("Unsupported key type " + key.getAlgorithm());
        };
    }

    private static byte[] algorithmIdentifier(PublicKey key) {
        return switch (signatureAlgorithm(key)) {
            case "SHA256withRSA" -> DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.1.11"), DerWriter.nullValue());
            case "SHA256withECDSA" -> DerWriter.sequence(DerWriter.oid("1.2.840.10045.4.3.2"));
            case "SHA384withECDSA" -> DerWriter.sequence(DerWriter.oid("1.2.840.10045.4.3.3"));
            default -> DerWriter.sequence(DerWriter.oid("1.3.101.112"));
        };
    }

    // ---- export ----

    public static String privateKeyPem(PrivateKey key) {
        return pem("PRIVATE KEY", key.getEncoded());
    }

    public static String publicKeyPem(PublicKey key) {
        return pem("PUBLIC KEY", key.getEncoded());
    }

    public static String certificatePem(X509Certificate cert) {
        return X509Inspector.toPem(cert);
    }

    /** A PKCS#12 keystore holding the private key and certificate under {@code alias}. */
    public static byte[] pkcs12(KeyPair keys, X509Certificate cert, String alias, char[] password)
            throws GeneralSecurityException, IOException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("A password is required to protect the PKCS#12 file");
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(alias, keys.getPrivate(), password, new Certificate[]{cert});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        return out.toByteArray();
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
