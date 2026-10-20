package com.ourgiant.crypt;

import javax.swing.*;
import java.awt.*;
import java.util.Random;

/** The "setec astronomy" announcement: the words unscramble into their anagram, "too many secrets". */
final class SetecDialog {

    static final String FROM = "SETEC ASTRONOMY";
    static final String TO = "TOO MANY SECRETS";
    private static final Color BACK = new Color(0x050805);
    private static final Color TEXT = new Color(0x8cff9e);

    private SetecDialog() {
    }

    static void show(Component parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        Window owner = SwingUtilities.getWindowAncestor(parent);
        JDialog d = new JDialog(owner, "Setec Astronomy", Dialog.ModalityType.APPLICATION_MODAL);
        JLabel words = new JLabel(FROM, SwingConstants.CENTER);
        words.setFont(new Font(Font.MONOSPACED, Font.BOLD, 34));
        words.setForeground(TEXT);
        JLabel note = new JLabel("<html><center>Decrypted and decoded output now resolves letter by letter.<br>"
                + "Type \"setec astronomy\" again to switch it off.</center></html>", SwingConstants.CENTER);
        note.setForeground(BACK); // invisible until the words settle; packed in now so the dialog doesn't grow
        JButton ok = new JButton("OK");
        ok.addActionListener(e -> d.dispose());

        JPanel p = new JPanel(new BorderLayout(0, 16));
        p.setBackground(BACK);
        p.setBorder(BorderFactory.createEmptyBorder(28, 36, 18, 36));
        p.add(words, BorderLayout.NORTH);
        p.add(note, BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttons.setOpaque(false);
        buttons.add(ok);
        p.add(buttons, BorderLayout.SOUTH);
        d.setContentPane(p);
        d.getRootPane().setDefaultButton(ok);
        // Size for the longer phrase so the dialog doesn't jump.
        words.setText(TO + " ");
        d.pack();
        words.setText(FROM);
        d.setLocationRelativeTo(owner);

        Random random = new Random();
        double[] at = TextReveal.revealTimes(TO.length(), random);
        String letters = FROM.replace(" ", "");
        long start = System.currentTimeMillis() + 900; // hold the original for a moment
        Timer t = new Timer(45, null);
        t.addActionListener(e -> {
            double progress = (System.currentTimeMillis() - start) / 1500.0;
            if (progress < 0) {
                return;
            }
            if (progress >= 1) {
                words.setText(TO);
                note.setForeground(TEXT.darker());
                t.stop();
                return;
            }
            words.setText(TextReveal.frame(TO, at, progress, random, letters));
        });
        t.start();
        d.setVisible(true);
        t.stop();
    }
}
