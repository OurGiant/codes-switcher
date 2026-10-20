package com.ourgiant.crypt;

import java.util.prefs.Preferences;

/**
 * Local app state: which update version the silent startup check has already notified about,
 * the selected UI theme, and the main window's layout. Never inputs, keys or passwords.
 */
public class AppPreferences {

    private static final String KEY_LAST_NOTIFIED_UPDATE_VERSION = "lastNotifiedUpdateVersion";
    private static final String KEY_THEME = "theme";
    private static final String DEFAULT_THEME = "Flat Light";
    private static final String KEY_LAST_SCREEN = "mainWindow.lastScreen";
    private static final String KEY_BOUNDS = "mainWindow.bounds";
    private static final String KEY_MAXIMIZED = "mainWindow.maximized";
    private static final String KEY_SIDEBAR_WIDTH = "mainWindow.sidebarWidth";

    private final Preferences prefs;

    public AppPreferences() {
        this(Preferences.userNodeForPackage(AppPreferences.class));
    }

    /** For tests: a separate preferences node so the real one isn't touched. */
    AppPreferences(Preferences prefs) {
        this.prefs = prefs;
    }

    /**
     * The version the silent startup update check last auto-opened the About box for, so it
     * doesn't nag on every single launch while a known update sits unapplied — once per new
     * version, not once per launch. Empty string if never notified.
     */
    public String getLastNotifiedUpdateVersion() {
        return prefs.get(KEY_LAST_NOTIFIED_UPDATE_VERSION, "");
    }

    public void setLastNotifiedUpdateVersion(String version) {
        prefs.put(KEY_LAST_NOTIFIED_UPDATE_VERSION, version);
    }

    public String getTheme() {
        return prefs.get(KEY_THEME, DEFAULT_THEME);
    }

    public void setTheme(String themeName) {
        prefs.put(KEY_THEME, themeName);
    }

    /** Title of the screen the main window last showed, or empty. */
    public String getLastScreen() {
        return prefs.get(KEY_LAST_SCREEN, "");
    }

    public void setLastScreen(String title) {
        prefs.put(KEY_LAST_SCREEN, title);
    }

    /** Last main window bounds, or null if never saved or unreadable. */
    public java.awt.Rectangle getWindowBounds() {
        String[] p = prefs.get(KEY_BOUNDS, "").split(",");
        if (p.length != 4) {
            return null;
        }
        try {
            return new java.awt.Rectangle(Integer.parseInt(p[0]), Integer.parseInt(p[1]),
                    Integer.parseInt(p[2]), Integer.parseInt(p[3]));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public void setWindowBounds(java.awt.Rectangle r) {
        prefs.put(KEY_BOUNDS, r.x + "," + r.y + "," + r.width + "," + r.height);
    }

    public boolean isMaximized() {
        return prefs.getBoolean(KEY_MAXIMIZED, false);
    }

    public void setMaximized(boolean maximized) {
        prefs.putBoolean(KEY_MAXIMIZED, maximized);
    }

    /** Sidebar width in pixels, or {@code fallback} if never saved. */
    public int getSidebarWidth(int fallback) {
        return prefs.getInt(KEY_SIDEBAR_WIDTH, fallback);
    }

    public void setSidebarWidth(int width) {
        prefs.putInt(KEY_SIDEBAR_WIDTH, width);
    }
}
