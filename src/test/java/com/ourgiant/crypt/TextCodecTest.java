package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TextCodecTest {

    @Test
    void base64RoundTrip() throws Exception {
        String encoded = TextCodec.encode("hello world", TextCodec.BASE64);
        assertEquals("aGVsbG8gd29ybGQ=", encoded);
        assertEquals("hello world", TextCodec.decode(encoded, TextCodec.BASE64));
    }

    @Test
    void urlRoundTrip() throws Exception {
        String encoded = TextCodec.encode("a b&c", TextCodec.URL);
        assertEquals("a+b%26c", encoded);
        assertEquals("a b&c", TextCodec.decode(encoded, TextCodec.URL));
    }

    @Test
    void htmlRoundTrip() throws Exception {
        String encoded = TextCodec.encode("<a href=\"x\">'/'</a>", TextCodec.HTML);
        assertEquals("&lt;a href=&quot;x&quot;&gt;&#x27;&#x2F;&#x27;&lt;&#x2F;a&gt;", encoded);
        assertEquals("<a href=\"x\">'/'</a>", TextCodec.decode(encoded, TextCodec.HTML));
    }

    @Test
    void hexRoundTrip() throws Exception {
        String encoded = TextCodec.encode("AB", TextCodec.HEX);
        assertEquals("4142", encoded);
        assertEquals("AB", TextCodec.decode(encoded, TextCodec.HEX));
    }

    @Test
    void hexDecodeRejectsOddLength() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("abc", TextCodec.HEX));
    }

    @Test
    void binaryRoundTrip() throws Exception {
        String encoded = TextCodec.encode("AB", TextCodec.BINARY);
        assertEquals("0100000101000010", encoded);
        assertEquals("AB", TextCodec.decode(encoded, TextCodec.BINARY));
    }

    @Test
    void binaryDecodeRejectsLengthNotDivisibleByEight() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("0100", TextCodec.BINARY));
    }

    @Test
    void rot13IsItsOwnInverse() throws Exception {
        String encoded = TextCodec.encode("Hello, World!", TextCodec.ROT13);
        assertEquals("Uryyb, Jbeyq!", encoded);
        assertEquals("Hello, World!", TextCodec.decode(encoded, TextCodec.ROT13));
    }

    @Test
    void jsonEscapeRoundTrip() throws Exception {
        String input = "line1\nline2\t\"quoted\"\\";
        String encoded = TextCodec.encode(input, TextCodec.JSON);
        assertEquals(input, TextCodec.decode(encoded, TextCodec.JSON));
    }

    @Test
    void jwtEncodingIsUnsupported() {
        assertThrows(UnsupportedOperationException.class, () -> TextCodec.encode("x", TextCodec.JWT));
    }

    @Test
    void hashesCannotBeDecoded() {
        assertThrows(UnsupportedOperationException.class, () -> TextCodec.decode("abc", TextCodec.SHA256));
        assertThrows(UnsupportedOperationException.class, () -> TextCodec.decode("abc", TextCodec.SHA512));
        assertThrows(UnsupportedOperationException.class, () -> TextCodec.decode("abc", TextCodec.MD5));
    }

    @Test
    void sha256KnownVector() throws Exception {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", TextCodec.encode("abc", TextCodec.SHA256));
    }

    @Test
    void sha512KnownVector() throws Exception {
        assertEquals(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                TextCodec.encode("abc", TextCodec.SHA512));
    }

    @Test
    void md5KnownVector() throws Exception {
        assertEquals("900150983cd24fb0d6963f7d28e17f72", TextCodec.encode("abc", TextCodec.MD5));
    }

    @Test
    void decodeJwtExtractsHeaderAndPayload() throws Exception {
        // {"alg":"HS256","typ":"JWT"} . {"sub":"1234567890","name":"John Doe"}
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
                + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        String result = TextCodec.decode(jwt, TextCodec.JWT);

        assertEquals(true, result.contains("HS256"));
        assertEquals(true, result.contains("John Doe"));
    }

    @Test
    void decodeJwtRejectsMalformedToken() {
        assertThrows(IllegalArgumentException.class, () -> TextCodec.decode("not.a.jwt.token", TextCodec.JWT));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "SHA-1 (Hash), a9993e364706816aba3e25717850c26c9cd0d89d",
            "SHA3-256 (Hash), 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "SHA3-512 (Hash), b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            "BLAKE2b-512 (Hash), ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    })
    void newHashesOfAbc(String method, String expected) throws Exception {
        assertEquals(expected, TextCodec.encode("abc", method));
        assertThrows(UnsupportedOperationException.class, () -> TextCodec.decode(expected, method));
    }
}
