package com.ourgiant.crypt.gpg;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Parsers for gpg's machine-readable output; samples captured from gpg 2.4. */
class GpgParsersTest {

    private static final String LISTING = """
            tru:o:1:1792420831:1:3:1:5
            pub:u:255:22:138455C5E300F9A9:1792420828:::u:::scESC:::::ed25519:::0:
            fpr:::::::::CDE4AEA10EAD4264214725D9138455C5E300F9A9:
            uid:u::::1792420828::E275056101A1B2246FBFBE8E2C85F1925D919036::Alice Example <alice@example.com>::::::::::0:
            sub:u:255:18:E539B4687B3F3D21:1792420828::::::e:::::cv25519::
            fpr:::::::::6EF92DFD88BE3D341A008F12E539B4687B3F3D21:
            pub:e:3072:1:AAAABBBBCCCCDDDD:1600000000:1700000000::-:::sc:::::::0:
            fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAABBBB:
            uid:e::::1600000000::X::Bob\\x3a Ops <bob@example.com>::::::::::0:
            uid:e::::1600000000::Y::Robert <rob@example.com>::::::::::0:
            """;

    @Test
    void parsesKeysFromColonListing() {
        List<GpgKey> keys = GpgKey.parseColons(LISTING);
        assertEquals(2, keys.size());

        GpgKey alice = keys.get(0);
        assertEquals("138455C5E300F9A9", alice.keyId());
        assertEquals("CDE4AEA10EAD4264214725D9138455C5E300F9A9", alice.fingerprint(), "primary fpr, not the subkey's");
        assertEquals("EdDSA ed25519", alice.algorithm());
        assertEquals(255, alice.bits());
        assertEquals(Instant.ofEpochSecond(1792420828), alice.created());
        assertNull(alice.expires());
        assertTrue(alice.canEncrypt() && alice.canSign());
        assertFalse(alice.expired());
        assertEquals(List.of("Alice Example <alice@example.com>"), alice.userIds());

        GpgKey bob = keys.get(1);
        assertEquals("RSA", bob.algorithm());
        assertEquals(List.of("Bob: Ops <bob@example.com>", "Robert <rob@example.com>"), bob.userIds(), "\\x3a unescaped");
        assertTrue(bob.expired());
        assertFalse(bob.canEncrypt());
        assertTrue(bob.canSign());
    }

    @Test
    void emptyListing() {
        assertTrue(GpgKey.parseColons("").isEmpty());
    }

    @Test
    void goodSignature() {
        GpgVerifyResult r = GpgVerifyResult.parseStatus("""
                [GNUPG:] NEWSIG
                [GNUPG:] KEY_CONSIDERED CDE4AEA10EAD4264214725D9138455C5E300F9A9 0
                [GNUPG:] SIG_ID D1+SxUfIkXqjnyWs6UcNqa497Jw 2026-10-19 1792420831
                [GNUPG:] GOODSIG 138455C5E300F9A9 Alice Example <alice@example.com>
                [GNUPG:] VALIDSIG CDE4AEA10EAD4264214725D9138455C5E300F9A9 2026-10-19 1792420831 0 4 0 22 10 00 CDE4AEA10EAD4264214725D9138455C5E300F9A9
                [GNUPG:] TRUST_ULTIMATE 0 pgp
                """);
        assertTrue(r.good());
        assertEquals("138455C5E300F9A9", r.keyId());
        assertEquals("Alice Example <alice@example.com>", r.signer());
        assertEquals("CDE4AEA10EAD4264214725D9138455C5E300F9A9", r.fingerprint());
        assertEquals(Instant.ofEpochSecond(1792420831), r.signedAt());
        assertEquals("ULTIMATE", r.trust());
    }

    @Test
    void badMissingExpiredAndEmpty() {
        assertEquals(GpgVerifyResult.Status.BAD,
                GpgVerifyResult.parseStatus("[GNUPG:] BADSIG 138455C5E300F9A9 Alice <a@x>").status());
        GpgVerifyResult missing = GpgVerifyResult.parseStatus("""
                [GNUPG:] ERRSIG 138455C5E300F9A9 22 10 00 1792420831 9 CDE4AEA10EAD4264214725D9138455C5E300F9A9
                [GNUPG:] NO_PUBKEY 138455C5E300F9A9
                """);
        assertEquals(GpgVerifyResult.Status.NO_PUBLIC_KEY, missing.status());
        assertEquals("138455C5E300F9A9", missing.keyId());
        assertEquals(GpgVerifyResult.Status.GOOD_EXPIRED_KEY,
                GpgVerifyResult.parseStatus("[GNUPG:] EXPKEYSIG ABCD Old Key <o@x>").status());
        assertEquals(GpgVerifyResult.Status.ERROR, GpgVerifyResult.parseStatus("[GNUPG:] NODATA 1").status());
        assertEquals(GpgVerifyResult.Status.ERROR, GpgVerifyResult.parseStatus("").status());
    }

    @Test
    void worstOfSeveralSignaturesWins() {
        GpgVerifyResult r = GpgVerifyResult.parseStatus("""
                [GNUPG:] GOODSIG AAAA Good <g@x>
                [GNUPG:] BADSIG BBBB Bad <b@x>
                """);
        assertEquals(GpgVerifyResult.Status.BAD, r.status());
    }
}
