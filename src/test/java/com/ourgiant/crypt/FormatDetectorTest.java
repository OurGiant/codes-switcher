package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FormatDetectorTest {

    private static String top(String input) {
        FormatDetector.Guess g = FormatDetector.bestDecodable(input);
        return g == null ? null : g.method();
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', value = {
            "aGVsbG8gd29ybGQ=                         | Base64",
            "SGVsbG8sIFdvcmxkIQ                       | Base64",
            "48656c6c6f2c20776f726c64                 | Hexadecimal",
            "deadbeef                                 | Hexadecimal",
            "0100000101000010                         | Binary",
            "MZXW6YTBOI======                         | Base32",
            "2NEpo7TZRRrLZSi2U                        | Base58",
            "<~9jqo^Bla~>                             | ASCII85",
            "hello%20world%21                         | URL",
            "&lt;b&gt;bold&lt;/b&gt;                  | HTML",
            "caf\\u00e9                               | Unicode Escape",
            "line one\\nline \\\"two\\\"              | JSON Escape",
            "H4sIAAAAAAAA/3MvOrzn8PxUhQ/zp0xQKEktLgEAtvZZ9REAAAA= | Gzip (as Base64)",
    })
    void detectsFormat(String input, String expected) {
        assertEquals(expected, top(input.strip()), () -> FormatDetector.detect(input.strip()).toString());
    }

    @Test
    void groupedHexAndBinaryStillDetected() {
        assertEquals(TextCodec.HEX, top("48 65 6c 6c 6f"));
        assertEquals(TextCodec.BINARY, top("01000001 01000010"));
    }

    @Test
    void wrappedBase64StillDetected() {
        assertEquals(TextCodec.BASE64, top("VGhpcyBpcyBhIGxvbmdlciBtZXNz\nYWdlIHdyYXBwZWQgb3ZlciBsaW5lcw=="));
    }

    @Test
    void base64OfBinaryDataStillDetected() {
        // 32 random bytes, as a key or ciphertext would be
        assertEquals(TextCodec.BASE64, top("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA="));
    }

    @Test
    void detectsJwt() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
                + "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        assertEquals(TextCodec.JWT, top(jwt));
    }

    @Test
    void pemIsReportedButNotDecodable() {
        List<FormatDetector.Guess> g = FormatDetector.detect("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        assertEquals(1, g.size());
        assertFalse(g.get(0).decodable());
        assertTrue(g.get(0).label().contains("certificate"));
    }

    @Test
    void sha256LengthHexGetsHashHint() {
        String sha = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        List<FormatDetector.Guess> g = FormatDetector.detect(sha);
        assertTrue(g.stream().anyMatch(x -> !x.decodable() && x.label().contains("SHA-256")), g::toString);
        assertEquals(TextCodec.HEX, top(sha));
    }

    @Test
    void appCipherOutputGetsHint() {
        List<FormatDetector.Guess> g = FormatDetector.detect("Q1MBAQAJJ8By1TZBrC0XgsBkLhhs3xOVx+dmn6I9Kj30hifs3MpeaBWSdzq7xt0JKSlMKvoNYasH2fdwE2TBJTLuvs9VZEQ=");
        assertEquals("AES / ChaCha20 output", g.get(0).label());
    }

    @Test
    void plainTextHasNoConfidentGuess() {
        for (String s : new String[]{"Hello, how are you today?", "The quick brown fox.", "just some words",
                "password", "", "   "}) {
            assertTrue(FormatDetector.detect(s).isEmpty(), () -> s + " -> " + FormatDetector.detect(s));
        }
    }

    @Test
    void everyDecodableGuessActuallyDecodes() throws Exception {
        String[] samples = {"aGVsbG8gd29ybGQ=", "48656c6c6f", "0100000101000010", "MZXW6YTBOI======",
                "hello%20world", "&amp;", "caf\\u00e9"};
        for (String s : samples) {
            FormatDetector.Guess g = FormatDetector.bestDecodable(s);
            assertNotNull(g, s);
            assertDoesNotThrow(() -> TextCodec.decode(s, g.method()), s + " as " + g.method());
        }
    }

    @Test
    void roundTripOfEveryCodecIsDetected() throws Exception {
        String text = "Detect me, please! 123";
        for (String method : new String[]{TextCodec.BASE64, TextCodec.BASE32, TextCodec.HEX, TextCodec.BINARY,
                TextCodec.GZIP, TextCodec.UNICODE}) {
            String encoded = TextCodec.encode(text + (method.equals(TextCodec.UNICODE) ? " é" : ""), method);
            assertEquals(method, top(encoded), () -> method + ": " + FormatDetector.detect(encoded));
        }
    }
}
