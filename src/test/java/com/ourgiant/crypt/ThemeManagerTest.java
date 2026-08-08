package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThemeManagerTest {

    @Test
    void listsFlatLightAsAnAvailableTheme() {
        List<String> names = Arrays.asList(ThemeManager.getAvailableThemeNames());
        assertTrue(names.contains("Flat Light"));
    }

    @Test
    void rejectsAnUnknownThemeName() {
        assertFalse(ThemeManager.applyTheme("Not A Real Theme"));
    }

    @Test
    void appliesEveryAdvertisedTheme() {
        for (String themeName : ThemeManager.getAvailableThemeNames()) {
            assertTrue(ThemeManager.applyTheme(themeName), "Failed to apply theme: " + themeName);
        }
    }
}
