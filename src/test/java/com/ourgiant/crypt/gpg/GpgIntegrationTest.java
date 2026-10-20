package com.ourgiant.crypt.gpg;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Drives the real gpg binary against throwaway keyrings. Skipped when gpg isn't installed.
 * Uses a short /tmp path because gpg-agent's socket path has a length limit.
 */
class GpgIntegrationTest {

    private static Path home;       // Alice (passphrase "alice-pw") and Bob (no passphrase)
    private static Path otherHome;  // Carol, whose public key "home" has never seen
    private static Path work;
    private static GpgOperations gpg;
    private static GpgOperations carolGpg;
    private static final List<String> log = new ArrayList<>();

    @BeforeAll
    static void setUp() throws Exception {
        assumeTrue(gpgAvailable(), "gpg not installed");
        home = Files.createTempDirectory(Path.of("/tmp"), "csg");
        otherHome = Files.createTempDirectory(Path.of("/tmp"), "csg");
        work = Files.createTempDirectory("gpgwork");
        Files.setPosixFilePermissions(home, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(otherHome, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        ProcessStarter starter = cmd -> new ProcessBuilder(cmd).start();
        gpg = new GpgOperations("gpg", starter, home);
        carolGpg = new GpgOperations("gpg", starter, otherHome);
        genKey(gpg, "Alice Example <alice@example.com>", "alice-pw");
        genKey(gpg, "Bob Example <bob@example.com>", "");
        genKey(carolGpg, "Carol Example <carol@example.com>", "");
    }

    @AfterAll
    static void tearDown() throws Exception {
        for (Path h : new Path[]{home, otherHome}) {
            if (h != null) {
                new ProcessBuilder("gpgconf", "--homedir", h.toString(), "--kill", "all").start().waitFor(10, TimeUnit.SECONDS);
                deleteTree(h);
            }
        }
        if (work != null) {
            deleteTree(work);
        }
    }

    @Test
    void listsPublicAndSecretKeys() throws Exception {
        List<GpgKey> pub = gpg.listKeys(false); // other tests may import Carol, so don't assume a count
        assertTrue(pub.stream().anyMatch(k -> k.primaryUserId().equals("Alice Example <alice@example.com>")));
        assertTrue(pub.stream().anyMatch(k -> k.primaryUserId().equals("Bob Example <bob@example.com>")));
        assertTrue(pub.stream().allMatch(k -> k.canEncrypt() && k.canSign() && k.fingerprint().length() == 40));
        List<GpgKey> sec = gpg.listKeys(true);
        assertEquals(2, sec.size(), "only Alice and Bob have secret keys here");
        assertTrue(sec.stream().allMatch(GpgKey::secret));
    }

    @Test
    void encryptAndSignThenDecrypt() throws Exception {
        Path in = write("plain.txt", "top secret ✓\n");
        Path out = work.resolve("plain.txt.asc");
        assertTrue(gpg.encryptFile(in.toString(), out.toString(), List.of("bob@example.com"), List.of(),
                true, false, "alice@example.com", "alice-pw", log::add), String.join("\n", log));
        assertTrue(Files.readString(out).startsWith("-----BEGIN PGP MESSAGE-----"));

        GpgOperations.Result dec = gpg.run(gpg.command("--batch", "--status-fd", "2", "--decrypt", out.toString()), null);
        assertEquals(0, dec.exitCode(), dec.stderr());
        assertEquals("top secret ✓\n", dec.stdout());
        assertTrue(dec.stderr().contains("GOODSIG"), "signed by Alice");
    }

    @Test
    void encryptToKeyFileNeedsTrustUnlessTicked() throws Exception {
        Path carolKey = work.resolve("carol.asc");
        GpgOperations.Result exp = carolGpg.run(carolGpg.command("--armor", "--export", "carol@example.com"), null);
        Files.writeString(carolKey, exp.stdout());
        Path in = write("for-carol.txt", "hi carol");

        // --recipient-file keys are used directly, so encryption works without importing.
        Path out = work.resolve("for-carol.gpg");
        assertTrue(gpg.encryptFile(in.toString(), out.toString(), List.of(), List.of(carolKey.toString()),
                false, false, null, null, log::add), String.join("\n", log));
        GpgOperations.Result dec = carolGpg.run(carolGpg.command("--batch", "--decrypt", out.toString()), null);
        assertEquals("hi carol", dec.stdout());

        // After importing, an untrusted keyring key is refused until "trust" is ticked.
        assertTrue(gpg.importKeys(carolKey.toString(), log::add));
        List<String> msgs = new ArrayList<>();
        Path out2 = work.resolve("for-carol2.gpg");
        assertFalse(gpg.encryptFile(in.toString(), out2.toString(), List.of("carol@example.com"), List.of(),
                false, false, null, null, msgs::add));
        assertTrue(msgs.stream().anyMatch(m -> m.startsWith("HINT:") && m.contains("Trust recipient keys")), msgs::toString);
        assertTrue(gpg.encryptFile(in.toString(), out2.toString(), List.of("carol@example.com"), List.of(),
                false, true, null, null, log::add));
    }

    @Test
    void detachedSignatureVerifiesAndDetectsTampering() throws Exception {
        Path data = write("release.tar", "release bytes");
        Path sig = work.resolve("release.tar.sig");
        assertTrue(gpg.signFile(data.toString(), sig.toString(), GpgOperations.SignMode.DETACHED, false,
                "alice@example.com", "alice-pw", log::add), String.join("\n", log));

        GpgVerifyResult ok = gpg.verifySignature(sig.toString(), data.toString(), log::add);
        assertEquals(GpgVerifyResult.Status.GOOD, ok.status());
        assertEquals("Alice Example <alice@example.com>", ok.signer());
        assertEquals("ULTIMATE", ok.trust());

        Files.writeString(data, "release bytes, modified");
        assertEquals(GpgVerifyResult.Status.BAD, gpg.verifySignature(sig.toString(), data.toString(), log::add).status());
    }

    @Test
    void clearsignedAndInlineVerify() throws Exception {
        Path data = write("note.txt", "I agree.\n");
        Path clear = work.resolve("note.txt.asc");
        assertTrue(gpg.signFile(data.toString(), clear.toString(), GpgOperations.SignMode.CLEARSIGN, true,
                "bob@example.com", "", log::add));
        assertTrue(Files.readString(clear).contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        assertTrue(gpg.verifySignature(clear.toString(), null, log::add).good());

        Path inline = work.resolve("note.txt.gpg");
        assertTrue(gpg.signFile(data.toString(), inline.toString(), GpgOperations.SignMode.INLINE, false,
                "bob@example.com", "", log::add));
        assertTrue(gpg.verifySignature(inline.toString(), null, log::add).good());
    }

    @Test
    void wrongPassphraseFailsWithHint() throws Exception {
        Path data = write("x.txt", "x");
        List<String> msgs = new ArrayList<>();
        assertFalse(gpg.signFile(data.toString(), work.resolve("x.sig").toString(), GpgOperations.SignMode.DETACHED,
                false, "alice@example.com", "wrong", msgs::add));
        assertTrue(msgs.stream().anyMatch(m -> m.contains("passphrase")), msgs::toString);
    }

    @Test
    void unknownSignerIsReported() throws Exception {
        Path data = write("from-carol.txt", "carol says hi");
        Path sig = work.resolve("from-carol.sig");
        assertTrue(carolGpg.signFile(data.toString(), sig.toString(), GpgOperations.SignMode.DETACHED, false,
                null, null, log::add));
        Path freshHome = Files.createTempDirectory(Path.of("/tmp"), "csg");
        try {
            GpgOperations fresh = new GpgOperations("gpg", c -> new ProcessBuilder(c).start(), freshHome);
            assertEquals(GpgVerifyResult.Status.NO_PUBLIC_KEY,
                    fresh.verifySignature(sig.toString(), data.toString(), log::add).status());
        } finally {
            new ProcessBuilder("gpgconf", "--homedir", freshHome.toString(), "--kill", "all").start().waitFor(10, TimeUnit.SECONDS);
            deleteTree(freshHome);
        }
    }

    @Test
    void noRecipientsIsRejectedBeforeRunningGpg() {
        List<String> msgs = new ArrayList<>();
        assertFalse(gpg.encryptFile("a", "b", List.of(), List.of(), false, false, null, null, msgs::add));
        assertTrue(msgs.get(0).contains("recipient"));
    }

    // ---------------------------------------------------------------- helpers

    private static void genKey(GpgOperations ops, String uid, String passphrase) throws IOException {
        GpgOperations.Result r = ops.run(ops.command("--batch", "--pinentry-mode", "loopback", "--passphrase", passphrase,
                "--quick-gen-key", uid, "default", "default", "never"), null);
        assertEquals(0, r.exitCode(), r.stderr());
    }

    private static Path write(String name, String content) throws IOException {
        return Files.writeString(work.resolve(name), content, StandardCharsets.UTF_8);
    }

    private static boolean gpgAvailable() {
        try {
            Process p = new ProcessBuilder("gpg", "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0
                    && System.getProperty("os.name").toLowerCase().contains("linux");
        } catch (Exception e) {
            return false;
        }
    }

    private static void deleteTree(Path p) throws IOException {
        try (var s = Files.walk(p)) {
            s.sorted(Comparator.reverseOrder()).forEach(f -> f.toFile().delete());
        }
    }
}
