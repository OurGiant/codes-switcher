package com.ourgiant.crypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;

/**
 * Application entry point and shared window helpers. Opens the {@link MainWindow}; pass
 * {@code --tool=NAME} (e.g. {@code gpg}, {@code jwt}, {@code x509}, {@code keygen}, {@code hash})
 * to start on a particular screen instead of the last one used.
 */
public final class AppLauncher {
    private static final Logger log = LoggerFactory.getLogger(AppLauncher.class);

    private AppLauncher() {
    }

    /** Shared by every window so the running app matches the packaged installer's icon, not just the jpackage-set one. */
    public static Image loadAppIcon() {
        java.net.URL url = AppLauncher.class.getResource("/app-icon.png");
        return url != null ? new ImageIcon(url).getImage() : null;
    }

    /**
     * Menu bar for a tool class used as its own window (the main window has its own). "Open Main
     * Window" closes this window and opens the main window on the same kind of screen.
     */
    public static JMenuBar createMenuBar(JFrame frame) {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");

        JMenuItem mainWindowItem = new JMenuItem("Open Main Window");
        mainWindowItem.addActionListener(e -> {
            frame.dispose();
            MainWindow.open(null);
        });
        fileMenu.add(mainWindowItem);

        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exitItem);

        menuBar.add(fileMenu);
        menuBar.add(createThemeMenu());

        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> new AboutDialog(frame).setVisible(true));
        helpMenu.add(aboutItem);
        menuBar.add(helpMenu);

        return menuBar;
    }

    static JMenu createThemeMenu() {
        JMenu themeMenu = new JMenu("Theme");
        AppPreferences preferences = new AppPreferences();
        String currentTheme = preferences.getTheme();

        ButtonGroup group = new ButtonGroup();
        for (String themeName : ThemeManager.getAvailableThemeNames()) {
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(themeName, themeName.equals(currentTheme));
            item.addActionListener(e -> {
                if (ThemeManager.applyTheme(themeName)) {
                    preferences.setTheme(themeName);
                } else {
                    log.warn("Failed to apply theme {}", themeName);
                }
            });
            group.add(item);
            themeMenu.add(item);
        }
        return themeMenu;
    }

    /** Applies the saved theme and opens the main window on {@code screen} (null: last used). */
    static void launch(String screen) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        SwingUtilities.invokeLater(() -> {
            if (!ThemeManager.applyTheme(new AppPreferences().getTheme())) {
                log.warn("Theme setup failed; falling back to default look and feel");
            }
            MainWindow.open(screen);
        });
    }

    public static void main(String[] args) {
        String screen = ScreenCatalog.toolArgument(args).map(tool -> {
            var entry = ScreenCatalog.resolve(tool);
            if (entry.isEmpty()) {
                log.warn("Unknown --tool value \"{}\"; opening the last-used screen", tool);
            }
            return entry.map(ScreenCatalog.Entry::title).orElse(null);
        }).orElse(null);
        launch(screen);
    }
}
