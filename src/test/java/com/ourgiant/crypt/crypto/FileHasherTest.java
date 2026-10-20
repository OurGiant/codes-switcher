package com.ourgiant.crypt.crypto;

import com.ourgiant.crypt.crypto.FileHasher.Algorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class FileHasherTest {

    @TempDir
    Path dir;

    /** Expected values from sha256sum, md5sum, sha1sum and Python hashlib for "hello file\n". */
    @ParameterizedTest
    @CsvSource({
            "SHA256, 702b7d2e4b28c4f3ef1434bd2333a83427796a9007fb2a23248becd4d51a3e7f",
            "SHA3_256, b65ecb2e28185c6e69276f56aba729d6c771cb4a38707367f2a224731a76e186",
            "SHA1, b816e2f4aca7186146e08dbc904149257a4c3531",
            "MD5, 14f21c9a90ca89a660e63f886a91bd4a",
            "BLAKE2B, a0a807d7838699bf54b574960c1a953ee7c9aac008e9f2ed8345e6da9cfbd7c428d37e13d6af6f4f88090b4ef014ee14444b0e325184632c1baefa0dc4efbb07",
    })
    void matchesCommandLineTools(Algorithm alg, String expected) throws Exception {
        Path f = dir.resolve("f.txt");
        Files.writeString(f, "hello file\n");
        assertEquals(expected, FileHasher.hash(f, alg, null));
    }

    @Test
    void largeFileStreamsAndReportsProgress() throws Exception {
        byte[] data = new byte[3 * 1024 * 1024 + 17];
        new Random(42).nextBytes(data);
        Path f = dir.resolve("big.bin");
        Files.write(f, data);
        AtomicLong last = new AtomicLong();
        String h = FileHasher.hash(f, Algorithm.SHA512, last::set);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-512").digest(data)), h);
        assertEquals(data.length, last.get());
        assertEquals(HexFormat.of().formatHex(Blake2b.hash512(data)), FileHasher.hash(f, Algorithm.BLAKE2B, null));
    }

    @Test
    void expectedHashFormsAreAccepted() {
        String h = "702b7d2e4b28c4f3ef1434bd2333a83427796a9007fb2a23248becd4d51a3e7f";
        assertTrue(FileHasher.matches(h.toUpperCase(), h));
        assertTrue(FileHasher.matches("  " + h + "\n", h));
        assertTrue(FileHasher.matches(h + "  installer.dmg", h));
        assertTrue(FileHasher.matches(h + " *installer.dmg", h));
        assertTrue(FileHasher.matches("SHA256 (installer.dmg) = " + h, h));
        assertTrue(FileHasher.matches("70:2b:7d:2e:4b:28:c4:f3:ef:14:34:bd:23:33:a8:34:27:79:6a:90:07:fb:2a:23:24:8b:ec:d4:d5:1a:3e:7f", h));
        assertFalse(FileHasher.matches(h.replace('7', '8'), h));
        assertFalse(FileHasher.matches("", h));
        assertFalse(FileHasher.matches(null, h));
    }

    @Test
    void suggestsAlgorithmsByLength() {
        assertEquals(List.of(Algorithm.SHA256, Algorithm.SHA3_256), FileHasher.candidatesFor("a".repeat(64)));
        assertEquals(List.of(Algorithm.MD5), FileHasher.candidatesFor("a".repeat(32)));
        assertTrue(FileHasher.candidatesFor("abc").isEmpty());
    }

    @Test
    void textCodecByteMethodsRoundTripBinaryData() throws Exception {
        byte[] data = new byte[1000];
        new Random(7).nextBytes(data);
        for (String m : com.ourgiant.crypt.TextCodec.BYTE_METHODS) {
            String enc = com.ourgiant.crypt.TextCodec.encodeBytes(data, m);
            if (m.endsWith("(Hash)")) {
                assertFalse(enc.isEmpty());
                continue;
            }
            assertArrayEquals(data, com.ourgiant.crypt.TextCodec.decodeBytes(enc, m), m);
        }
    }

    @Test
    void byteAndTextEncodingAgreeForUtf8() throws Exception {
        byte[] utf8 = "Grüße".getBytes(StandardCharsets.UTF_8);
        for (String m : com.ourgiant.crypt.TextCodec.BYTE_METHODS) {
            assertEquals(com.ourgiant.crypt.TextCodec.encode("Grüße", m),
                    com.ourgiant.crypt.TextCodec.encodeBytes(utf8, m), m);
        }
    }

    @Test
    void textOnlyMethodsRefuseBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> com.ourgiant.crypt.TextCodec.encodeBytes(new byte[1], com.ourgiant.crypt.TextCodec.URL));
        assertThrows(IllegalArgumentException.class,
                () -> com.ourgiant.crypt.TextCodec.decodeBytes("x", com.ourgiant.crypt.TextCodec.SHA256));
    }
}
