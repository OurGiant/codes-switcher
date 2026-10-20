package com.ourgiant.crypt;

import com.ourgiant.crypt.EasterEggs.Egg;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class EasterEggsTest {

    @AfterEach
    void allOff() {
        for (Egg e : Egg.values()) {
            EasterEggs.set(e, false);
        }
        MagicWord.resetForTests();
        MagicWord.notifier = c -> { };
    }

    @Test
    void codeWordsMatchIgnoringCaseSpacesAndPunctuation() {
        assertEquals(Optional.of(Egg.SETEC), EasterEggs.match("Setec Astronomy"));
        assertEquals(Optional.of(Egg.SETEC), EasterEggs.match("too many secrets!"));
        assertEquals(Optional.of(Egg.JOSHUA), EasterEggs.match("JOSHUA"));
        assertEquals(Optional.of(Egg.JOSHUA), EasterEggs.match("Shall we play a game?"));
        assertEquals(Optional.of(Egg.RABBIT), EasterEggs.match("white-rabbit"));
        assertEquals(Optional.of(Egg.RABBIT), EasterEggs.match("Follow the white rabbit."));
        assertEquals(Optional.of(Egg.PLANET), EasterEggs.match("HACK THE PLANET!!"));
        assertEquals(Optional.of(Egg.COURIER), EasterEggs.match("mnemonic"));
        assertEquals(Optional.empty(), EasterEggs.match("hack"));
        assertEquals(Optional.empty(), EasterEggs.match("rabbit"));
        assertEquals(Optional.empty(), EasterEggs.match(""));
        assertEquals(Optional.empty(), EasterEggs.match(null));
    }

    @Test
    void noCodeWordFindsATool() {
        // Typing one shows an empty sidebar, so nothing gives the eggs away before Enter.
        for (Egg e : Egg.values()) {
            for (String w : e.words()) {
                assertTrue(ScreenCatalog.filter(w).isEmpty(), w + " matches a tool");
                assertTrue(ScreenCatalog.resolve(w).isEmpty(), w + " resolves to a tool");
            }
        }
    }

    @Test
    void togglesNotifyOnlyOnChangeAndCourierStaysInSync() {
        AtomicInteger calls = new AtomicInteger();
        EasterEggs.addListener(calls::incrementAndGet);
        EasterEggs.set(Egg.SETEC, true);
        EasterEggs.set(Egg.SETEC, true);
        assertTrue(EasterEggs.isOn(Egg.SETEC));
        EasterEggs.set(Egg.SETEC, false);
        assertEquals(2, calls.get());

        EasterEggs.set(Egg.COURIER, true);
        assertTrue(CourierMode.isOn());
        CourierMode.set(false);
        assertFalse(EasterEggs.isOn(Egg.COURIER));
    }

    @Test
    void revealFramesKeepWhitespaceAndEndExact() {
        String text = "Too many\nsecrets: 42 of them.";
        Random r = new Random(7);
        double[] at = TextReveal.revealTimes(text.length(), r);
        String start = TextReveal.frame(text, at, 0, r);
        assertEquals(text.length(), start.length());
        for (int i = 0; i < text.length(); i++) {
            if (Character.isWhitespace(text.charAt(i))) {
                assertEquals(text.charAt(i), start.charAt(i), "whitespace moved at " + i);
            }
        }
        assertNotEquals(text, start);
        assertEquals(text, TextReveal.frame(text, at, 1.0, r));
        for (double t : at) {
            assertTrue(t >= 0 && t <= 1.0);
        }
    }

    @Test
    void setecAnnouncementIsAnAnagram() {
        assertEquals(sorted(SetecDialog.FROM), sorted(SetecDialog.TO));
    }

    private static String sorted(String s) {
        char[] c = s.replace(" ", "").toCharArray();
        java.util.Arrays.sort(c);
        return new String(c);
    }

    @Test
    void magicWordAfterThreeWrongInARowOncePerSession() {
        AtomicInteger shown = new AtomicInteger();
        MagicWord.notifier = c -> shown.incrementAndGet();
        MagicWord.wrong(null);
        MagicWord.wrong(null);
        MagicWord.right();
        MagicWord.wrong(null);
        MagicWord.wrong(null);
        assertEquals(0, shown.get(), "a correct password resets the count");
        MagicWord.wrong(null);
        assertEquals(1, shown.get());
        for (int i = 0; i < 6; i++) {
            MagicWord.wrong(null);
        }
        assertEquals(1, shown.get(), "only once per session");
    }

    @Test
    void matrixRainReplacesProgressBarsAndSurvivesThemeChanges() {
        try {
            EasterEggs.set(Egg.RABBIT, true);
            MatrixProgressBarUI.setEnabled(true);
            assertInstanceOf(MatrixProgressBarUI.class, new javax.swing.JProgressBar().getUI());
            assertTrue(ThemeManager.applyTheme("Flat Dark"));
            assertInstanceOf(MatrixProgressBarUI.class, new javax.swing.JProgressBar().getUI());
        } finally {
            EasterEggs.set(Egg.RABBIT, false);
            MatrixProgressBarUI.setEnabled(false);
        }
        assertFalse(new javax.swing.JProgressBar().getUI() instanceof MatrixProgressBarUI);
    }
}
