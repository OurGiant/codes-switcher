package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ExtraCodecsTest {

    private static final String[] SAMPLES = {"", "f", "fo", "foo", "foob", "fooba", "foobar",
            "Hello, wörld! 🔐", "line1\nline2\ttab"};

    @Test
    void base32Rfc4648Vectors() throws Exception {
        String[] expected = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], TextCodec.encode(SAMPLES[i], TextCodec.BASE32), SAMPLES[i]);
            assertEquals(SAMPLES[i], TextCodec.decode(expected[i], TextCodec.BASE32));
        }
    }

    @Test
    void base32DecodeIsLenient() throws Exception {
        assertEquals("foobar", TextCodec.decode("mzxw 6ytb\noi", TextCodec.BASE32));
    }

    @Test
    void base32RejectsBadChars() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("MZ1W", TextCodec.BASE32));
    }

    @Test
    void base58KnownVector() throws Exception {
        assertEquals("2NEpo7TZRRrLZSi2U", TextCodec.encode("Hello World!", TextCodec.BASE58));
        assertEquals("Hello World!", TextCodec.decode("2NEpo7TZRRrLZSi2U", TextCodec.BASE58));
    }

    @Test
    void base58KeepsLeadingZeroBytes() {
        byte[] data = {0, 0, 1, 2, (byte) 0xff};
        String enc = ExtraCodecs.base58Encode(data);
        assertTrue(enc.startsWith("11"));
        assertArrayEquals(data, ExtraCodecs.base58Decode(enc));
        assertArrayEquals(new byte[]{0}, ExtraCodecs.base58Decode("1"));
        assertArrayEquals(new byte[0], ExtraCodecs.base58Decode(""));
    }

    @Test
    void base58HighByteNotMistakenForSign() {
        byte[] data = {(byte) 0x80};
        assertArrayEquals(data, ExtraCodecs.base58Decode(ExtraCodecs.base58Encode(data)));
    }

    @Test
    void base58RejectsAmbiguousChars() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("0OIl", TextCodec.BASE58));
    }

    @Test
    void ascii85KnownVectors() throws Exception {
        assertEquals("9jqo^Bla", TextCodec.encode("Man is", TextCodec.ASCII85));
        assertEquals("z@:E^", ExtraCodecs.ascii85Encode(new byte[]{0, 0, 0, 0, 'a', 'b', 'c'}));
        assertEquals("Man is", TextCodec.decode("<~9jqo^Bla~>", TextCodec.ASCII85));
        assertArrayEquals(new byte[]{0, 0, 0, 0, 'a', 'b', 'c'}, ExtraCodecs.ascii85Decode("z@:E^"));
    }

    @Test
    void ascii85RejectsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("9jqo^B", TextCodec.ASCII85));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("abc{", TextCodec.ASCII85));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("uuuuu", TextCodec.ASCII85));
    }

    @Test
    void roundTripsForAllNewFormats() throws Exception {
        for (String method : new String[]{TextCodec.BASE32, TextCodec.BASE58, TextCodec.ASCII85,
                TextCodec.GZIP, TextCodec.DEFLATE, TextCodec.UNICODE}) {
            for (String s : SAMPLES) {
                assertEquals(s, TextCodec.decode(TextCodec.encode(s, method), method), method + ": " + s);
            }
        }
    }

    @Test
    void gzipDecodesOutputOfStandardGzip() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("compressed elsewhere".getBytes(StandardCharsets.UTF_8));
        }
        String b64 = Base64.getEncoder().encodeToString(bos.toByteArray());
        assertEquals("compressed elsewhere", TextCodec.decode(b64, TextCodec.GZIP));
    }

    @Test
    void deflateKnownPythonVector() throws Exception {
        // python3 -c "import zlib,base64;c=zlib.compressobj(wbits=-15);print(base64.b64encode(c.compress(b'hello')+c.flush()))"
        assertEquals("hello", TextCodec.decode("y0jNyckHAA==", TextCodec.DEFLATE));
    }

    @Test
    void compressedDecodeRejectsGarbage() {
        String junk = Base64.getEncoder().encodeToString("not compressed".getBytes());
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode(junk, TextCodec.GZIP));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode(junk, TextCodec.DEFLATE));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("%%%", TextCodec.GZIP));
    }

    @Test
    void decompressionBombIsRefused() throws Exception {
        byte[] zeros = new byte[ExtraCodecs.MAX_INFLATED_BYTES + 1];
        String bomb = ExtraCodecs.gzipEncode(zeros);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ExtraCodecs.gzipDecode(bomb));
        assertTrue(e.getMessage().contains("larger than"));
    }

    @Test
    void unicodeEscapeFormat() throws Exception {
        assertEquals("caf\\u00e9 \\ud83d\\udd10 a\\\\b", TextCodec.encode("café 🔐 a\\b", TextCodec.UNICODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\\u00E9", "\\u{e9}", "\\u{1F510}"})
    void unicodeUnescapeForms(String in) throws Exception {
        String out = TextCodec.decode(in, TextCodec.UNICODE);
        assertTrue(out.equals("é") || out.equals("🔐"), out);
    }

    @Test
    void unicodeUnescapeSurrogatePair() throws Exception {
        assertEquals("🔐", TextCodec.decode("\\uD83D\\uDD10", TextCodec.UNICODE));
    }

    @Test
    void unicodeUnescapeErrors() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("\\u12", TextCodec.UNICODE));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("\\uZZZZ", TextCodec.UNICODE));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("\\u{110000}", TextCodec.UNICODE));
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("\\u{41", TextCodec.UNICODE));
    }

    @Test
    void unicodeLeavesOtherBackslashesAlone() throws Exception {
        assertEquals("a\\nb", TextCodec.decode("a\\nb", TextCodec.UNICODE));
    }
}
