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

    public static boolean applyTheme(String themeName) {
        String className = AVAILABLE_THEMES.get(themeName);
        if (className == null) {
            logger.warn("Theme not found: {}", themeName);
            return false;
        }

        FlatAnimatedLafChange.showSnapshot();

        try {
            LookAndFeel currentLaf = UIManager.getLookAndFeel();
            if (currentLaf != null && currentLaf.getName().contains("Nimbus")) {
                flushStaleNimbusDefaults();
            }

            LookAndFeel laf = (LookAndFeel) Class.forName(className)
                .getDeclaredConstructor()
                .newInstance();
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
