package com.ourgiant.crypt.gpg;

import java.time.Instant;

/** Outcome of {@code gpg --verify}, read from its machine-readable {@code --status-fd} output. */
public record GpgVerifyResult(
        Status status,
        String keyId,
        String signer,        // user ID, when gpg knows the key
        String fingerprint,   // from VALIDSIG
        Instant signedAt,
        String trust,         // ULTIMATE, FULLY, MARGINAL, UNDEFINED, NEVER, or null
        String detail) {

    public enum Status {
        /** Signature is cryptographically valid and the key is usable. */
        GOOD,
        /** Valid signature, but the signing key has expired. */
        GOOD_EXPIRED_KEY,
        /** Valid signature, but the signing key has been revoked. */
        GOOD_REVOKED_KEY,
        /** Signature does not match the data — modified or wrong file. */
        BAD,
        /** The public key isn't in the keyring, so the signature can't be checked. */
        NO_PUBLIC_KEY,
        /** No signature found, or gpg failed for another reason. */
        ERROR
    }

    public boolean good() {
        return status == Status.GOOD;
    }

    public static GpgVerifyResult parseStatus(String statusOutput) {
        Status status = null;
        String keyId = null;
        String signer = null;
        String fpr = null;
        Instant when = null;
        String trust = null;
        String detail = null;
        for (String line : statusOutput.split("\\r?\\n")) {
            if (!line.startsWith("[GNUPG:] ")) {
                continue;
            }
            String[] f = line.substring(9).split(" ", 3);
            String rest = f.length > 2 ? f[2] : "";
            switch (f[0]) {
                case "GOODSIG" -> { status = worse(status, Status.GOOD); keyId = arg(f, 1); signer = GpgKey.unescape(rest); }
                case "EXPKEYSIG" -> { status = worse(status, Status.GOOD_EXPIRED_KEY); keyId = arg(f, 1); signer = GpgKey.unescape(rest); }
                case "REVKEYSIG" -> { status = worse(status, Status.GOOD_REVOKED_KEY); keyId = arg(f, 1); signer = GpgKey.unescape(rest); }
                case "BADSIG" -> { status = worse(status, Status.BAD); keyId = arg(f, 1); signer = GpgKey.unescape(rest); }
                case "ERRSIG" -> {
                    keyId = arg(f, 1);
                    String[] e = line.substring(9).split(" ");
                    boolean missingKey = e.length > 6 && "9".equals(e[6]);
                    status = worse(status, missingKey ? Status.NO_PUBLIC_KEY : Status.ERROR);
                }
                case "NO_PUBKEY" -> { status = worse(status, Status.NO_PUBLIC_KEY); keyId = arg(f, 1); }
                case "VALIDSIG" -> {
                    String[] v = line.substring(9).split(" ");
                    fpr = v.length > 1 ? v[1] : null;
                    when = v.length > 3 ? parseTime(v[3]) : null;
                }
                case "TRUST_ULTIMATE", "TRUST_FULLY", "TRUST_MARGINAL", "TRUST_UNDEFINED", "TRUST_NEVER" ->
                        trust = f[0].substring(6);
                case "NODATA" -> { status = worse(status, Status.ERROR); detail = "No signature found in the file"; }
                default -> { }
            }
        }
        if (status == null) {
            status = Status.ERROR;
            detail = detail != null ? detail : "gpg reported no signature status";
        }
        return new GpgVerifyResult(status, keyId, signer, fpr, when, trust, detail);
    }

    /** With several signatures, report the worst one. */
    private static Status worse(Status a, Status b) {
        return a == null || b.ordinal() > a.ordinal() ? b : a;
    }

    private static String arg(String[] f, int i) {
        return f.length > i ? f[i] : null;
    }

    private static Instant parseTime(String s) {
        try {
            return Instant.ofEpochSecond(Long.parseLong(s));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
