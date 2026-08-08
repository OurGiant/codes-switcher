package com.ourgiant.crypt;

import com.ourgiant.crypt.util.UpdateChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.util.Optional;

public class AppLauncher extends JFrame {
    private static final Logger log = LoggerFactory.getLogger(AppLauncher.class);

    private final AppPreferences preferences = new AppPreferences();

    public AppLauncher() {
        setTitle("Codes Switcher v" + AppVersion.get());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(360, 180);
        setLocationRelativeTo(null);
        setLayout(new GridLayout(0, 1, 10, 10));
        Image icon = loadAppIcon();
        if (icon != null) {
            setIconImage(icon);
        }

        JLabel label = new JLabel("Choose a tool", SwingConstants.CENTER);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 16f));

        JButton gpgButton = new JButton("GPG Decryptor");
        gpgButton.addActionListener(e -> {
            new GPGDecryptor().setVisible(true);
            dispose();
        });

        JButton encodingButton = new JButton("Encoder / Decoder");
        encodingButton.addActionListener(e -> {
            new EncodingDecodingApp().setVisible(true);
            dispose();
        });

        ((JPanel) getContentPane()).setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        add(label);
        add(gpgButton);
        add(encodingButton);

        setJMenuBar(createMenuBar(this));
        checkForUpdateAndNotifyIfNewer();
    }

    /** Shared by every window so the running app matches the packaged installer's icon, not just the jpackage-set one. */
    public static Image loadAppIcon() {
        java.net.URL url = AppLauncher.class.getResource("/app-icon.png");
        return url != null ? new ImageIcon(url).getImage() : null;
    }

    public static JMenuBar createMenuBar(JFrame frame) {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");

        JMenuItem switchAppsItem = new JMenuItem("Switch Apps");
        switchAppsItem.addActionListener(e -> {
            frame.dispose();
            new AppLauncher().setVisible(true);
        });
        fileMenu.add(switchAppsItem);

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

    private static JMenu createThemeMenu() {
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

    /**
     * Silent unless there's actually something to say: no UI at all if up to date or the check
     * fails, and only once per newly-released version (not once per launch) if there's an
     * update — otherwise a known update sitting unapplied would pop this on every single
     * startup. A user can still always check manually via Help > About regardless of this
     * state. This is the app's only outbound network call, and it never blocks launch since it
     * runs in its own SwingWorker.
     */
    private void checkForUpdateAndNotifyIfNewer() {
        SwingWorker<Optional<UpdateChecker.ReleaseInfo>, Void> worker = new SwingWorker<>() {
            @Override
            protected Optional<UpdateChecker.ReleaseInfo> doInBackground() {
                return UpdateChecker.fetchLatestRelease();
            }

            @Override
            protected void done() {
                Optional<UpdateChecker.ReleaseInfo> release;
                try {
                    release = get();
                } catch (Exception e) {
                    log.warn("Silent startup update check failed", e);
                    return;
                }
                if (release.isEmpty()) {
                    return;
                }
                UpdateChecker.ReleaseInfo info = release.get();
                if (!UpdateChecker.isNewerVersion(info.version(), AppVersion.get())) {
                    return;
                }
                if (info.version().equals(preferences.getLastNotifiedUpdateVersion())) {
                    return;
                }
                preferences.setLastNotifiedUpdateVersion(info.version());
                new AboutDialog(AppLauncher.this, info).setVisible(true);
            }
        };
        worker.execute();
    }

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        if (!ThemeManager.applyTheme(new AppPreferences().getTheme())) {
            log.warn("Theme setup failed; falling back to default look and feel");
        }

        SwingUtilities.invokeLater(() -> new AppLauncher().setVisible(true));
    }
}
