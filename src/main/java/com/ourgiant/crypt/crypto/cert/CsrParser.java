package com.ourgiant.crypt.crypto.cert;

import com.ourgiant.crypt.crypto.asn1.Der;
import com.ourgiant.crypt.crypto.asn1.Der.Node;

import javax.security.auth.x500.X500Principal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Parses and checks a PKCS#10 certificate signing request (CSR). */
public final class CsrParser {

    private static final String EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
    private static final String SUBJECT_ALT_NAME = "2.5.29.17";

    private static final Map<String, String> SIGNATURE_ALGS = Map.of(
            "1.2.840.113549.1.1.5", "SHA1withRSA",
            "1.2.840.113549.1.1.11", "SHA256withRSA",
            "1.2.840.113549.1.1.12", "SHA384withRSA",
            "1.2.840.113549.1.1.13", "SHA512withRSA",
            "1.2.840.10045.4.3.2", "SHA256withECDSA",
            "1.2.840.10045.4.3.3", "SHA384withECDSA",
            "1.2.840.10045.4.3.4", "SHA512withECDSA",
            "1.3.101.112", "Ed25519",
            "1.3.101.113", "Ed448");

    public record Csr(
            String subject,
            PublicKey publicKey,
            String keyDescription,
            String signatureAlgorithm,
            Boolean signatureValid,   // null when the algorithm isn't supported here
            List<String> requestedSans) {
    }

    private CsrParser() {
    }

    public static boolean looksLikeCsr(String text) {
        return text != null && (text.contains("BEGIN CERTIFICATE REQUEST") || text.contains("BEGIN NEW CERTIFICATE REQUEST"));
    }

    public static Csr parsePem(String pem) {
        StringBuilder b64 = new StringBuilder();
        boolean inside = false;
        for (String line : pem.split("\\r?\\n")) {
            String t = line.strip();
            if (t.startsWith("-----BEGIN") && t.contains("CERTIFICATE REQUEST")) {
                inside = true;
            } else if (t.startsWith("-----END")) {
                if (inside) {
                    break;
                }
            } else if (inside) {
                b64.append(t);
            }
        }
        if (b64.isEmpty()) {
            throw new X509Inspector.CertParseException("No CERTIFICATE REQUEST block found");
        }
        try {
            return parse(Base64.getDecoder().decode(b64.toString()));
        } catch (IllegalArgumentException e) {
            throw new X509Inspector.CertParseException("CSR is not valid: " + e.getMessage(), e);
        }
    }

    public static Csr parse(byte[] der) {
        try {
            Node root = Der.parse(der).expect(Der.SEQUENCE);
            Node info = root.child(0).expect(Der.SEQUENCE);
            String sigOid = root.child(1).expect(Der.SEQUENCE).child(0).oid();
            byte[] signature = root.child(2).bitString();

            List<Node> infoParts = info.children();
            if (infoParts.size() < 3) {
                throw new Der.DerException("CertificationRequestInfo is incomplete");
            }
            if (infoParts.get(0).integer().intValue() != 0) {
                throw new Der.DerException("Unsupported CSR version " + infoParts.get(0).integer());
            }
            String subject = new X500Principal(infoParts.get(1).expect(Der.SEQUENCE).encoded())
                    .getName(X500Principal.RFC2253);
            PublicKey key = publicKey(infoParts.get(2).expect(Der.SEQUENCE).encoded());

            List<String> sans = new ArrayList<>();
            if (infoParts.size() > 3 && infoParts.get(3).contextTag() == 0) {
                for (Node attr : infoParts.get(3).children()) {
                    if (EXTENSION_REQUEST.equals(attr.child(0).oid())) {
                        for (Node extensions : attr.child(1).children()) {
                            for (Node ext : extensions.children()) {
                                if (SUBJECT_ALT_NAME.equals(ext.child(0).oid())) {
                                    Node value = ext.children().get(ext.children().size() - 1).expect(Der.OCTET_STRING);
                                    sans.addAll(generalNames(Der.parse(value.content())));
                                }
                            }
                        }
                    }
                }
            }

            String jca = SIGNATURE_ALGS.get(sigOid);
            Boolean valid = null;
            if (jca != null) {
                Signature s = Signature.getInstance(jca);
                s.initVerify(key);
                s.update(info.encoded());
                valid = s.verify(signature);
            }
            return new Csr(subject, key, describe(key), jca != null ? jca : "unsupported (" + sigOid + ")", valid, sans);
        } catch (Der.DerException | GeneralSecurityException e) {
            throw new X509Inspector.CertParseException("Failed to parse CSR: " + e.getMessage(), e);
        }
    }

    private static PublicKey publicKey(byte[] spki) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spki);
        for (String alg : new String[]{"RSA", "EC", "Ed25519", "Ed448"}) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(spec);
            } catch (GeneralSecurityException ignored) {
                // try the next type
            }
        }
        throw new GeneralSecurityException("Unsupported public key type");
    }

    static String describe(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return "RSA " + rsa.getModulus().bitLength() + " bits";
        }
        if (key instanceof ECPublicKey ec) {
            return "EC " + ec.getParams().getCurve().getField().getFieldSize() + " bits";
        }
        if (key instanceof java.security.interfaces.EdECPublicKey ed) {
            return ed.getParams().getName();
        }
        return key.getAlgorithm();
    }

    private static List<String> generalNames(Node seq) {
        List<String> out = new ArrayList<>();
        for (Node n : seq.children()) {
            byte[] v = n.content();
            switch (n.contextTag()) {
                case 1 -> out.add("email:" + new String(v, StandardCharsets.US_ASCII));
                case 2 -> out.add("DNS:" + new String(v, StandardCharsets.US_ASCII));
                case 6 -> out.add("URI:" + new String(v, StandardCharsets.US_ASCII));
                case 7 -> {
                    try {
                        out.add("IP:" + InetAddress.getByAddress(v).getHostAddress());
                    } catch (UnknownHostException e) {
                        out.add("IP:(invalid)");
                    }
                }
                default -> out.add("other[" + n.contextTag() + "]");
            }
        }
        return out;
    }
}
