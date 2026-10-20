package com.ourgiant.crypt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class CourierModeTest {

    @AfterEach
    void off() {
        CourierMode.set(false);
    }

    @Test
    void codeWordIgnoresCaseSpacesAndPunctuation() {
        assertTrue(CourierMode.isCodeWord("mnemonic"));
        assertTrue(CourierMode.isCodeWord("  MNEMONIC "));
        assertTrue(CourierMode.isCodeWord("Johnny Mnemonic"));
        assertTrue(CourierMode.isCodeWord("johnny-mnemonic!"));
        assertFalse(CourierMode.isCodeWord("mnemo"));
        assertFalse(CourierMode.isCodeWord("hide"));
        assertFalse(CourierMode.isCodeWord(""));
        assertFalse(CourierMode.isCodeWord(null));
    }

    @Test
    void codeWordIsNotAToolSearchTerm() {
        // Typing it shows nothing in the sidebar, so the egg stays hidden until Enter.
        assertTrue(ScreenCatalog.filter(CourierMode.CODE_WORD).isEmpty());
    }

    @Test
    void listenersRunOnlyOnChange() {
        AtomicInteger calls = new AtomicInteger();
        CourierMode.addListener(calls::incrementAndGet);
        CourierMode.set(true);
        CourierMode.set(true);
        assertTrue(CourierMode.isOn());
        CourierMode.set(false);
        assertEquals(2, calls.get());
    }

    @Test
    void aboutBoxWinksOnlyInCourierMode() {
        assertEquals("", AboutDialog.courierLine());
        CourierMode.set(true);
        assertTrue(AboutDialog.courierLine().contains("Courier Mode online"));
    }
}
