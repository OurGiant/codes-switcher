package com.ourgiant.crypt.crypto.cert;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses and inspects an X.509 certificate: subject/issuer/validity/SANs/key-usage/fingerprint,
 * plus the three risk flags the tracking issue asked for (expired, self-signed, weak key).
 * {@link java.security.cert.CertificateFactory} handles both PEM (it strips the
 * "-----BEGIN/END CERTIFICATE-----" wrapper itself) and raw DER transparently - no hand-rolled
 * PEM parsing needed here, unlike the JWT side's PEM public keys.
 */
public final class X509Inspector {

    private static final int WEAK_RSA_BITS = 2048;
    private static final int WEAK_EC_BITS = 224;

    // Index -> label, matching X509Certificate#getKeyUsage()'s documented bit order.
    private static final String[] KEY_USAGE_LABELS = {
        "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
    };

    private X509Inspector() {
    }

    public static final class CertParseException extends RuntimeException {
        public CertParseException(String message, Throwable cause) {
            super(message, cause);
        }

        public CertParseException(String message) {
            super(message);
        }
    }

    public record Inspection(
        String subject,
        String issuer,
        Instant notBefore,
        Instant notAfter,
        List<String> subjectAlternativeNames,
        List<String> keyUsages,
        String sha256Fingerprint,
        String keyAlgorithm,
        int keySizeBits,
        boolean expired,
        boolean notYetValid,
        boolean selfSigned,
        boolean selfSignatureValid,
        boolean weakKey,
        String weakKeyDetail) {
    }

    /** Parses one certificate. For a PEM bundle with multiple certs, use parseChain instead. */
    public static X509Certificate parseSingle(String pemOrDer) {
        List<X509Certificate> certs = parseChain(pemOrDer);
        if (certs.size() != 1) {
            throw new CertParseException("Expected exactly one certificate, found " + certs.size());
        }
        return certs.get(0);
    }

    /** Parses one or more concatenated PEM certificates (or a single DER certificate). */
    public static List<X509Certificate> parseChain(String pemOrDer) {
        if (pemOrDer == null || pemOrDer.isBlank()) {
            throw new CertParseException("No certificate data provided");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            byte[] bytes = pemOrDer.getBytes(StandardCharsets.UTF_8);
            List<X509Certificate> certs = new ArrayList<>();
            for (var cert : factory.generateCertificates(new ByteArrayInputStream(bytes))) {
                certs.add((X509Certificate) cert);
            }
            if (certs.isEmpty()) {
                throw new CertParseException("No certificates found in the provided data");
            }
            return certs;
        } catch (CertificateException e) {
            throw new CertParseException("Failed to parse certificate: " + e.getMessage(), e);
        }
    }

    public static Inspection inspect(X509Certificate cert) {
        Instant now = Instant.now();
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();
        boolean expired = now.isAfter(notAfter);
        boolean notYetValid = now.isBefore(notBefore);

        String subject = cert.getSubjectX500Principal().getName();
        String issuer = cert.getIssuerX500Principal().getName();
        boolean selfSigned = subject.equals(issuer);
        boolean selfSignatureValid = selfSigned && verifiesAgainstOwnKey(cert);

        KeySizeInfo keySize = keySizeOf(cert.getPublicKey());
        boolean weakKey = keySize.isWeak();

        return new Inspection(
            subject,
            issuer,
            notBefore,
            notAfter,
            subjectAlternativeNames(cert),
            keyUsages(cert),
            sha256Fingerprint(cert),
            keySize.algorithm(),
            keySize.bits(),
            expired,
            notYetValid,
            selfSigned,
            selfSignatureValid,
            weakKey,
            weakKey ? keySize.weakDetail() : null);
    }

    private static boolean verifiesAgainstOwnKey(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            // A cert whose subject == issuer but doesn't actually self-verify is a stronger
            // "something's off here" signal than the name-equality heuristic alone.
            return false;
        }
    }

    private static List<String> subjectAlternativeNames(X509Certificate cert) {
        List<String> names = new ArrayList<>();
        try {
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> entry : sans) {
                    names.add(sanTypeLabel((Integer) entry.get(0)) + ": " + entry.get(1));
                }
            }
        } catch (CertificateException e) {
            names.add("(unable to parse SANs: " + e.getMessage() + ")");
        }
        return names;
    }

    private static String sanTypeLabel(int generalNameType) {
        // GeneralName types per RFC 5280 4.2.1.6 - only labeling the common ones.
        return switch (generalNameType) {
            case 1 -> "email";
            case 2 -> "DNS";
            case 6 -> "URI";
            case 7 -> "IP";
            default -> "type" + generalNameType;
        };
    }

    private static List<String> keyUsages(X509Certificate cert) {
        boolean[] usage = cert.getKeyUsage();
        if (usage == null) {
            return List.of();
        }
        List<String> labels = new ArrayList<>();
        for (int i = 0; i < usage.length && i < KEY_USAGE_LABELS.length; i++) {
            if (usage[i]) {
                labels.add(KEY_USAGE_LABELS[i]);
            }
        }
        return labels;
    }

    private static String sha256Fingerprint(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X:", b));
            }
            sb.setLength(sb.length() - 1); // trailing ':'
            return sb.toString();
        } catch (Exception e) {
            throw new CertParseException("Failed to compute fingerprint: " + e.getMessage(), e);
        }
    }

    private record KeySizeInfo(String algorithm, int bits, boolean isWeak, String weakDetail) {
    }

    private static KeySizeInfo keySizeOf(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            boolean weak = bits < WEAK_RSA_BITS;
            return new KeySizeInfo("RSA", bits, weak,
                weak ? "RSA " + bits + "-bit key is below the " + WEAK_RSA_BITS + "-bit minimum" : null);
        }
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            boolean weak = bits < WEAK_EC_BITS;
            return new KeySizeInfo("EC", bits, weak,
                weak ? "EC " + bits + "-bit curve is below the " + WEAK_EC_BITS + "-bit minimum" : null);
        }
        return new KeySizeInfo(key.getAlgorithm(), -1, false, null);
    }
}
