package com.ourgiant.crypt.crypto.cert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Basic certificate chain validation: for a leaf-first ordered chain (leaf, intermediate(s),
 * optionally root), checks that each certificate's signature actually verifies against the next
 * certificate's public key. Deliberately "basic" per the tracking issue's scope - this is a
 * signature-chain walk, not full PKIX policy validation (no revocation checking, no name
 * constraints, no policy OIDs) - good enough to catch "these certs don't actually chain
 * together" without pulling in the ceremony of a full PKIXParameters/CertPathValidator setup.
 */
public final class ChainValidator {

    private ChainValidator() {
    }

    public record LinkResult(String subject, String verifiedAgainst, boolean signatureValid, String detail) {
    }

    public record ChainResult(List<LinkResult> links, boolean allValid) {
    }

    /** No-op (empty result, trivially valid) when fewer than 2 certificates are supplied. */
    public static ChainResult validate(List<X509Certificate> leafFirstChain) {
        List<LinkResult> links = new ArrayList<>();
        boolean allValid = true;
        for (int i = 0; i < leafFirstChain.size() - 1; i++) {
            X509Certificate cert = leafFirstChain.get(i);
            X509Certificate issuerCert = leafFirstChain.get(i + 1);
            boolean valid;
            String detail;
            try {
                cert.verify(issuerCert.getPublicKey());
                valid = true;
                detail = "Signature verifies against the next certificate's public key";
            } catch (Exception e) {
                valid = false;
                detail = "Signature does NOT verify against the next certificate: " + e.getMessage();
            }
            allValid = allValid && valid;
            links.add(new LinkResult(
                cert.getSubjectX500Principal().getName(),
                issuerCert.getSubjectX500Principal().getName(),
                valid,
                detail));
        }
        return new ChainResult(links, allValid);
    }
}
