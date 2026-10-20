package com.ourgiant.crypt;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * Something that can show a tool's screens: the main window. The tool classes
 * ({@link EncodingDecodingApp}, {@link CryptoInspectorApp}, {@link GPGDecryptor}) still work as
 * their own windows, but when hosted they hand their screens over with {@code detachScreens}.
 */
public interface ScreenHost {

    /** One screen, identified by the title it had as a tab in its original window. */
    record Screen(String title, JComponent content) {
    }

    /** Shows the screen with this title (e.g. after "Open in Verifier"). */
    void showScreen(String title);

    /** The component dialogs should be centred on. */
    Component dialogOwner();

    /** Moves every tab out of {@code tabs} into a list of screens, in order. */
    static List<Screen> drain(JTabbedPane tabs) {
        java.util.ArrayList<Screen> out = new java.util.ArrayList<>();
        while (tabs.getTabCount() > 0) {
            out.add(new Screen(tabs.getTitleAt(0), (JComponent) tabs.getComponentAt(0)));
            tabs.removeTabAt(0);
        }
        return out;
    }
}
