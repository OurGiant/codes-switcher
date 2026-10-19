package com.ourgiant.crypt.crypto;

import com.ourgiant.crypt.crypto.HmacGenerator.Algorithm;
import com.ourgiant.crypt.crypto.HmacGenerator.KeyFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** RFC 4231 test cases 1 and 2, plus key parsing. */
class HmacGeneratorTest {

    @Test
    void rfc4231Case1HexKey() throws Exception {
        String key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                HmacGenerator.compute("Hi There", key, KeyFormat.HEX, Algorithm.SHA256).hex());
        assertEquals("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                        + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                HmacGenerator.compute("Hi There", key, KeyFormat.HEX, Algorithm.SHA512).hex());
    }

    @Test
    void rfc4231Case2TextKey() throws Exception {
        String msg = "what do ya want for nothing?";
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                HmacGenerator.compute(msg, "Jefe", KeyFormat.TEXT, Algorithm.SHA256).hex());
        assertEquals("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                        + "8e2240ca5e69e2c78b3239ecfab21649",
                HmacGenerator.compute(msg, "Jefe", KeyFormat.TEXT, Algorithm.SHA384).hex());
    }

    @Test
    void sha1KnownVector() throws Exception {
        assertEquals("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
                HmacGenerator.compute("The quick brown fox jumps over the lazy dog", "key",
                        KeyFormat.TEXT, Algorithm.SHA1).hex());
    }

    @Test
    void base64AndUrlRenderingsAgree() throws Exception {
        HmacGenerator.Result r = HmacGenerator.compute("m", "Jefe", KeyFormat.TEXT, Algorithm.SHA256);
        assertEquals(r.base64().replace('+', '-').replace('/', '_').replace("=", ""), r.base64Url());
    }

    @Test
    void base64KeyAcceptsUrlAlphabet() throws Exception {
        // "Jefe" as Base64 is SmVmZQ==
        assertEquals(HmacGenerator.compute("x", "Jefe", KeyFormat.TEXT, Algorithm.SHA256),
                HmacGenerator.compute("x", "SmVmZQ", KeyFormat.BASE64, Algorithm.SHA256));
    }

    @Test
    void badKeysRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> HmacGenerator.compute("x", "", KeyFormat.TEXT, Algorithm.SHA256));
        assertThrows(IllegalArgumentException.class,
                () -> HmacGenerator.compute("x", "abc", KeyFormat.HEX, Algorithm.SHA256));
        assertThrows(IllegalArgumentException.class,
                () -> HmacGenerator.compute("x", "zz", KeyFormat.HEX, Algorithm.SHA256));
        assertThrows(IllegalArgumentException.class,
                () -> HmacGenerator.compute("x", "!!!!", KeyFormat.BASE64, Algorithm.SHA256));
    }
}
