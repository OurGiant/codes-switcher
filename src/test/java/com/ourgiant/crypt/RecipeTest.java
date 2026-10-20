package com.ourgiant.crypt;

import com.ourgiant.crypt.Recipe.Direction;
import com.ourgiant.crypt.Recipe.Step;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RecipeTest {

    @Test
    void runsLayeredDecode() throws Exception {
        // "secret" -> gzip(base64) -> URL-encoded
        String layered = TextCodec.encode(TextCodec.encode("secret message", TextCodec.GZIP), TextCodec.URL);
        Recipe r = new Recipe(List.of(new Step(Direction.DECODE, TextCodec.URL),
                new Step(Direction.DECODE, TextCodec.GZIP)));
        List<Recipe.StepResult> out = r.run(layered);
        assertEquals(2, out.size());
        assertTrue(out.stream().allMatch(Recipe.StepResult::ok));
        assertEquals("secret message", out.get(1).output());
    }

    @Test
    void stopsAtFailingStepWithMessage() {
        Recipe r = new Recipe(List.of(new Step(Direction.DECODE, TextCodec.BASE64),
                new Step(Direction.DECODE, TextCodec.HEX),
                new Step(Direction.ENCODE, TextCodec.ROT13)));
        List<Recipe.StepResult> out = r.run("aGVsbG8="); // "hello" is not hex
        assertEquals(2, out.size());
        assertTrue(out.get(0).ok());
        assertEquals("hello", out.get(0).output());
        assertFalse(out.get(1).ok());
        assertNotNull(out.get(1).error());
    }

    @Test
    void textRoundTrip() {
        Recipe r = new Recipe(List.of(new Step(Direction.ENCODE, TextCodec.BASE64),
                new Step(Direction.ENCODE, TextCodec.SHA256)));
        assertEquals("encode Base64\nencode SHA-256 (Hash)\n", r.toText());
        assertEquals(r.steps(), Recipe.parse(r.toText()).steps());
    }

    @Test
    void parseIsForgiving() {
        Recipe r = Recipe.parse("# my recipe\n\n  DECODE url  \r\ndecode base64\n");
        assertEquals(List.of(new Step(Direction.DECODE, TextCodec.URL), new Step(Direction.DECODE, TextCodec.BASE64)),
                r.steps());
    }

    @Test
    void parseErrorsNameTheLine() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Recipe.parse("decode Base64\nfrobnicate Hex"))
                .getMessage().startsWith("Line 2"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Recipe.parse("decode Klingon"))
                .getMessage().contains("unknown method"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Recipe.parse("decode MD5 (Hash)"))
                .getMessage().contains("one-way"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Recipe.parse("encode JWT (Decode Only)"))
                .getMessage().contains("only decode"));
        assertThrows(IllegalArgumentException.class, () -> Recipe.parse("decode"));
    }

    @Test
    void emptyRecipeReturnsNoResults() {
        assertTrue(new Recipe(List.of()).run("x").isEmpty());
    }

    @Test
    void everyMethodIsListedOnce() {
        assertEquals(TextCodec.METHODS.size(), TextCodec.METHODS.stream().distinct().count());
        assertTrue(TextCodec.isHash(TextCodec.BLAKE2B));
        assertFalse(TextCodec.isHash(TextCodec.BASE64));
    }
}
