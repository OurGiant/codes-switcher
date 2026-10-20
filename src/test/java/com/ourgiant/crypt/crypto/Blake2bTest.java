package com.ourgiant.crypt.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/** Vectors from RFC 7693 Appendix A and Python's hashlib.blake2b. */
class Blake2bTest {

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void rfc7693Abc() {
        assertEquals("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                        + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                hex(Blake2b.hash512("abc".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void empty() {
        assertEquals("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", hex(Blake2b.hash512(new byte[0])));
    }

    @Test
    void exactlyOneBlock() {
        assertEquals("865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf7"
                + "98e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41", hex(Blake2b.hash512(new byte[128])));
    }

    @Test
    void multipleBlocksStreamedInOddChunks() {
        byte[] data = new byte[768];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        String expected = "323e97a7a859ee63c9013debb0ca995811e73117a2f574723416e596ebc184e3"
                + "7a59b66d2f597df4a7c1b0d1d41a1a7f28774f46a6864d56c57b9d6c5f7302fb";
        assertEquals(expected, hex(Blake2b.hash512(data)));

        Blake2b b = new Blake2b(64);
        int off = 0;
        int[] chunks = {1, 127, 128, 129, 3, 380};
        for (int n : chunks) {
            b.update(data, off, n);
            off += n;
        }
        assertEquals(data.length, off);
        assertEquals(expected, hex(b.digest()));
    }

    @Test
    void rejectsBadLength() {
        assertThrows(IllegalArgumentException.class, () -> new Blake2b(0));
        assertThrows(IllegalArgumentException.class, () -> new Blake2b(65));
    }
}
