package com.ourgiant.crypt;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/**
 * The "magic word" egg (a nod to <i>Jurassic Park</i>): after three wrong passwords in a row, a
 * small notice that closes itself. Shown at most once per session; a correct password resets the
 * count. It only ever learns "wrong" or "right", never the password.
 */
final class MagicWord {

    static final int LIMIT = 3;
    static final String TEXT = "Ah ah ah, you didn't say the magic word.";

    private static int wrongInARow;
    private static boolean shown;
    /** What showing the notice does; tests replace it. */
    static Consumer<Component> notifier = MagicWord::showNotice;

    private MagicWord() {
    }

    static synchronized void wrong(Component parent) {
        wrongInARow++;
        if (wrongInARow >= LIMIT && !shown) {
            shown = true;
            notifier.accept(parent);
        }
    }

    static synchronized void right() {
        wrongInARow = 0;
    }

    static synchronized void resetForTests() {
        wrongInARow = 0;
        shown = false;
    }

    private static void showNotice(Component parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
        JDialog d = new JDialog(owner, "Access denied", Dialog.ModalityType.MODELESS);
        JLabel big = new JLabel(TEXT);
        big.setFont(big.getFont().deriveFont(Font.BOLD, big.getFont().getSize2D() * 1.4f));
        JLabel hint = new JLabel("<html>That's three wrong passwords in a row. Check Caps Lock, the algorithm, "
                + "and, for a three-image key, that you picked the same images.</html>");
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));
        p.add(big, BorderLayout.NORTH);
        p.add(hint, BorderLayout.CENTER);
        JButton ok = new JButton("OK");
        ok.addActionListener(e -> d.dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttons.add(ok);
        p.add(buttons, BorderLayout.SOUTH);
        d.setContentPane(p);
        d.pack();
        d.setSize(Math.min(d.getWidth(), 520), d.getHeight() + 20);
        d.setLocationRelativeTo(owner);
        d.setFocusableWindowState(false); // never steals the cursor from the password field
        d.setVisible(true);
        Timer close = new Timer(8000, e -> d.dispose());
        close.setRepeats(false);
        close.start();
    }
}
