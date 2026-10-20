package com.ourgiant.crypt;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatAnimatedLafChange;
import com.formdev.flatlaf.intellijthemes.FlatArcDarkOrangeIJTheme;
import com.formdev.flatlaf.intellijthemes.FlatOneDarkIJTheme;
import com.formdev.flatlaf.intellijthemes.FlatSolarizedDarkIJTheme;
import com.formdev.flatlaf.intellijthemes.materialthemeuilite.FlatMTGitHubDarkIJTheme;
import com.formdev.flatlaf.intellijthemes.materialthemeuilite.FlatMTGitHubIJTheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.Window;
import java.util.LinkedHashMap;
import java.util.Map;

/** Theme manager for FlatLaf/IntelliJ themes, ported from doc-scrubber/aws-idp-saml-ui. */
public class ThemeManager {
    private static final Logger logger = LoggerFactory.getLogger(ThemeManager.class);

    private static final Map<String, String> AVAILABLE_THEMES = new LinkedHashMap<>();

    static {
        AVAILABLE_THEMES.put("Flat Light", FlatLightLaf.class.getName());
        AVAILABLE_THEMES.put("GitHub Light", FlatMTGitHubIJTheme.class.getName());
        AVAILABLE_THEMES.put("GitHub Dark", FlatMTGitHubDarkIJTheme.class.getName());
        AVAILABLE_THEMES.put("Flat Dark", FlatDarkLaf.class.getName());
        AVAILABLE_THEMES.put("Darcula", FlatDarculaLaf.class.getName());
        AVAILABLE_THEMES.put("One Dark", FlatOneDarkIJTheme.class.getName());
        AVAILABLE_THEMES.put("Arc Dark Orange", FlatArcDarkOrangeIJTheme.class.getName());
        AVAILABLE_THEMES.put("Solarized Dark", FlatSolarizedDarkIJTheme.class.getName());
    }

    private ThemeManager() {
    }

    public static String[] getAvailableThemeNames() {
        return AVAILABLE_THEMES.keySet().toArray(new String[0]);
    }

    /** Courier Mode's neon-on-black look: Flat Dark with its colour variables overridden. Not in the Theme menu. */
    static final Map<String, String> COURIER_COLORS = Map.of(
            "@background", "#0a110c",
            "@foreground", "#b6ffb0",
            "@accentColor", "#39ff14",
            "@componentBackground", "#0f1a12",
            "@buttonBackground", "#13241a",
            "@selectionBackground", "#1f6b2a",
            "@selectionForeground", "#eaffe6");

    public static boolean applyCourierTheme() {
        FlatDarkLaf laf = new FlatDarkLaf();
        laf.setExtraDefaults(COURIER_COLORS);
        return apply(laf, "Courier");
    }

    public static boolean applyTheme(String themeName) {
        String className = AVAILABLE_THEMES.get(themeName);
        if (className == null) {
            logger.warn("Theme not found: {}", themeName);
            return false;
        }
        try {
            return apply((LookAndFeel) Class.forName(className).getDeclaredConstructor().newInstance(), themeName);
        } catch (ReflectiveOperationException e) {
            logger.error("Failed to create theme: {}", themeName, e);
            return false;
        }
    }

    private static boolean apply(LookAndFeel laf, String themeName) {
        FlatAnimatedLafChange.showSnapshot();

        try {
            LookAndFeel currentLaf = UIManager.getLookAndFeel();
            if (currentLaf != null && currentLaf.getName().contains("Nimbus")) {
                flushStaleNimbusDefaults();
            }

            UIManager.setLookAndFeel(laf);

            refreshDisplayableWindows();

            logger.info("Applied theme: {}", themeName);
            return true;
        } catch (Exception e) {
            logger.error("Failed to apply theme: {}", themeName, e);
            return false;
        } finally {
            FlatAnimatedLafChange.hideSnapshotWithAnimation();
        }
    }

    private static void flushStaleNimbusDefaults() {
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
            refreshDisplayableWindows();
        } catch (Exception e) {
            logger.warn("Failed to flush stale Nimbus defaults via intermediate LaF; proceeding with direct theme switch", e);
        }
    }

    private static void refreshDisplayableWindows() {
        for (Window window : Window.getWindows()) {
            if (!window.isDisplayable()) {
                continue;
            }
            SwingUtilities.updateComponentTreeUI(window);
            window.revalidate();
            window.repaint();
        }
    }
}
