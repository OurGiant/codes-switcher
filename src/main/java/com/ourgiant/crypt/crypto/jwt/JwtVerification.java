package com.ourgiant.crypt.crypto.jwt;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;

/**
 * Orchestrates parsing + signature verification + expiry checking into one call per key-material
 * type. The three entry points (HMAC secret / public key / JWKS) are deliberately separate
 * methods rather than one "verify(jwt, keyMaterial)" dispatcher that infers what to do from the
 * token's own "alg" header - that inference is exactly the alg-confusion bug class (RFC 8725
 * 3.1/3.2): trusting the token to say what kind of key should verify it lets an attacker who
 * knows a service's RSA public key forge an HS256 token using those public key bytes as the HMAC
 * secret. Here, the caller (the person who pasted an HMAC secret vs. a public key vs. a JWKS
 * URL) is what determines which family of algorithms is even attempted; a token whose "alg"
 * doesn't match that family is rejected before any cryptographic operation runs, not silently
 * reinterpreted.
 */
public final class JwtVerification {

    public enum TimeStatus { VALID, EXPIRED, NOT_YET_VALID, NO_TIME_CLAIMS }

    public record Outcome(
        JwtParser.ParsedJwt token,
        boolean algorithmMatchesKeyType,
        Boolean signatureValid,       // null if verification wasn't attempted (alg mismatch / error)
        String error,                 // non-null on a parse/mismatch/verification error
        TimeStatus timeStatus,
        String timeDetail) {
    }

    private JwtVerification() {
    }

    public static Outcome verifyHmac(String jwt, byte[] secret) {
        return verify(jwt, parsed -> {
            if (!HmacVerifier.supports(parsed.algorithm())) {
                return mismatch(parsed, "You provided an HMAC secret, but the token's algorithm is \""
                    + parsed.algorithm() + "\" (not HS256/384/512) - refusing to verify. "
                    + "This is exactly the kind of algorithm-confusion mismatch that shouldn't be silently allowed.");
            }
            boolean valid = HmacVerifier.verify(parsed.signingInput(), parsed.signature(), parsed.algorithm(), secret);
            return matched(parsed, valid, null);
        });
    }

    public static Outcome verifyWithPublicKey(String jwt, PublicKey key) {
        return verify(jwt, parsed -> verifyAgainstKey(parsed, key));
    }

    /** Resolves the verification key from a JWKS URL by the token's "kid", then verifies as usual. */
    public static Outcome verifyWithJwks(String jwt, String jwksUrl) {
        JwtParser.ParsedJwt parsed;
        try {
            parsed = JwtParser.parse(jwt);
        } catch (JwtParser.MalformedJwtException e) {
            return new Outcome(null, false, null, e.getMessage(), TimeStatus.NO_TIME_CLAIMS, null);
        }
        try {
            String jwksJson = JwksFetcher.fetch(jwksUrl);
            PublicKey key = JwksKeys.findKey(jwksJson, parsed.keyId());
            return verify(jwt, ignored -> verifyAgainstKey(parsed, key));
        } catch (JwksKeys.JwksException e) {
            return new Outcome(parsed, false, null, e.getMessage(), timeStatus(parsed).status(), timeStatus(parsed).detail());
        }
    }

    private static Outcome verifyAgainstKey(JwtParser.ParsedJwt parsed, PublicKey key) {
        boolean keyIsRsa = key instanceof RSAPublicKey;
        boolean keyIsEc = key instanceof ECPublicKey;

        if (keyIsRsa && !RsaEcVerifier.supportsRsa(parsed.algorithm())) {
            return mismatch(parsed, "You provided an RSA public key, but the token's algorithm is \""
                + parsed.algorithm() + "\" (not RS256/384/512) - refusing to verify.");
        }
        if (keyIsEc && !RsaEcVerifier.supportsEc(parsed.algorithm())) {
            return mismatch(parsed, "You provided an EC public key, but the token's algorithm is \""
                + parsed.algorithm() + "\" (not ES256/384/512) - refusing to verify.");
        }
        if (!keyIsRsa && !keyIsEc) {
            return mismatch(parsed, "Unsupported public key type: " + key.getAlgorithm());
        }

        try {
            boolean valid = RsaEcVerifier.verify(parsed.signingInput(), parsed.signature(), parsed.algorithm(), key);
            return matched(parsed, valid, null);
        } catch (IllegalArgumentException e) {
            // Right algorithm family, but e.g. wrong key size/curve for this specific key.
            return matched(parsed, false, e.getMessage());
        }
    }

    private interface Verifier {
        Outcome verify(JwtParser.ParsedJwt parsed);
    }

    private static Outcome verify(String jwt, Verifier verifier) {
        JwtParser.ParsedJwt parsed;
        try {
            parsed = JwtParser.parse(jwt);
        } catch (JwtParser.MalformedJwtException e) {
            return new Outcome(null, false, null, e.getMessage(), TimeStatus.NO_TIME_CLAIMS, null);
        }
        try {
            return verifier.verify(parsed);
        } catch (Exception e) {
            return matched(parsed, false, e.getMessage());
        }
    }

    private static Outcome mismatch(JwtParser.ParsedJwt parsed, String message) {
        var time = timeStatus(parsed);
        return new Outcome(parsed, false, null, message, time.status(), time.detail());
    }

    private static Outcome matched(JwtParser.ParsedJwt parsed, boolean signatureValid, String error) {
        var time = timeStatus(parsed);
        return new Outcome(parsed, true, signatureValid, error, time.status(), time.detail());
    }

    // Package-private (not private) so JwtVerificationTest can call the Clock-injectable
    // timeStatus() overload directly for deterministic time-based assertions.
    record TimeStatusResult(TimeStatus status, String detail) {
    }

    private static TimeStatusResult timeStatus(JwtParser.ParsedJwt parsed) {
        return timeStatus(parsed, Clock.systemUTC());
    }

    /** Package-private clock override for deterministic tests. */
    static TimeStatusResult timeStatus(JwtParser.ParsedJwt parsed, Clock clock) {
        if (parsed.exp() == null && parsed.nbf() == null) {
            return new TimeStatusResult(TimeStatus.NO_TIME_CLAIMS, "Token has no \"exp\" or \"nbf\" claim");
        }
        Instant now = Instant.now(clock);
        if (parsed.exp() != null && now.getEpochSecond() >= parsed.exp()) {
            return new TimeStatusResult(TimeStatus.EXPIRED,
                "Expired at " + Instant.ofEpochSecond(parsed.exp()));
        }
        if (parsed.nbf() != null && now.getEpochSecond() < parsed.nbf()) {
            return new TimeStatusResult(TimeStatus.NOT_YET_VALID,
                "Not valid until " + Instant.ofEpochSecond(parsed.nbf()));
        }
        String detail = parsed.exp() != null ? "Expires at " + Instant.ofEpochSecond(parsed.exp()) : "No expiry set";
        return new TimeStatusResult(TimeStatus.VALID, detail);
    }
}
