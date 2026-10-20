package com.ourgiant.crypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CopyFormatTest {

    private static final String TRICKY = "say \"hi\"\\ok\n\tline2\r\u0001\u2028é🔐";

    @Test
    void rawIsUnchanged() {
        assertEquals(TRICKY, CopyFormat.RAW.format(TRICKY));
    }

    @Test
    void jsonStringParsesBackToTheOriginal() throws Exception {
        String lit = CopyFormat.JSON.format(TRICKY);
        assertEquals("\"say \\\"hi\\\"\\\\ok\\n\\tline2\\r\\u0001\\u2028é🔐\"", lit);
        assertEquals(TRICKY, new ObjectMapper().readValue(lit, String.class));
    }

    @Test
    void javaStringEscapes() {
        assertEquals("\"a\\\"b\\\\c\\nd\"", CopyFormat.JAVA.format("a\"b\\c\nd"));
    }

    @Test
    void pythonUsesHexEscapesForControlBytes() {
        assertEquals("\"x\\x01y\\u2028\"", CopyFormat.PYTHON.format("x\u0001y\u2028"));
    }

    @Test
    void markdownFenceOutgrowsBackticksInside() {
        assertEquals("```\nplain\n```\n", CopyFormat.MARKDOWN.format("plain"));
        assertEquals("```\nends with newline\n```\n", CopyFormat.MARKDOWN.format("ends with newline\n"));
        assertEquals("`````\nhas ```` four\n`````\n", CopyFormat.MARKDOWN.format("has ```` four"));
    }

    @Test
    void labelsAreDistinct() {
        assertEquals(CopyFormat.values().length,
                java.util.Arrays.stream(CopyFormat.values()).map(CopyFormat::label).distinct().count());
    }
}
