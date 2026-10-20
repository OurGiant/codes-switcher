package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class SessionHistoryTest {

    @Test
    void newestFirstAndCapped() {
        SessionHistory h = new SessionHistory();
        for (int i = 0; i < SessionHistory.MAX_ENTRIES + 7; i++) {
            h.record("Text Codecs", "Encode " + i, "in" + i, "out" + i, () -> { });
        }
        assertEquals(SessionHistory.MAX_ENTRIES, h.entries().size());
        assertEquals("Encode " + (SessionHistory.MAX_ENTRIES + 6), h.entries().get(0).operation());
        assertEquals("Encode 7", h.entries().get(SessionHistory.MAX_ENTRIES - 1).operation());
    }

    @Test
    void oversizedValuesAreCutAndCannotBeRestored() {
        SessionHistory h = new SessionHistory();
        String big = "x".repeat(SessionHistory.MAX_CHARS + 1000);
        SessionHistory.Entry e = h.record("Recipe", "Run", big, "small", () -> { });
        assertTrue(e.truncated());
        assertFalse(e.canRestore(), "restoring a cut input would silently use the wrong data");
        assertTrue(e.input().length() < big.length());
        assertTrue(e.input().endsWith("KB)"));
        assertEquals("small", e.output());

        SessionHistory.Entry ok = h.record("Recipe", "Run", "a", "b", () -> { });
        assertFalse(ok.truncated());
        assertTrue(ok.canRestore());
    }

    @Test
    void clearAndListeners() {
        SessionHistory h = new SessionHistory();
        AtomicInteger calls = new AtomicInteger();
        Runnable l = calls::incrementAndGet;
        h.addListener(l);
        h.record("HMAC", "HMAC-SHA256", "m", "tag", null);
        h.clear();
        assertTrue(h.entries().isEmpty());
        assertEquals(2, calls.get());
        h.removeListener(l);
        h.record("HMAC", "HMAC-SHA256", "m", "tag", null);
        assertEquals(2, calls.get());
    }

    @Test
    void nullsBecomeEmptyAndIdsIncrease() {
        SessionHistory h = new SessionHistory();
        SessionHistory.Entry a = h.record("X", "op", null, null, null);
        SessionHistory.Entry b = h.record("X", "op", "", "", null);
        assertEquals("", a.input());
        assertTrue(b.id() > a.id());
        assertFalse(a.canRestore());
    }

    @Test
    void preview() {
        assertEquals("a b c", SessionHistory.preview("  a\n b\t c ", 20));
        assertEquals("abcd…", SessionHistory.preview("abcdefgh", 5));
    }
}
