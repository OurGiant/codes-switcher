package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.PasswordStrength;
import com.ourgiant.crypt.crypto.PasswordStrength.Rating;
import com.ourgiant.crypt.crypto.PasswordStrength.Result;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Arrays;
import java.util.Random;

/**
 * The "joshua" egg (a nod to <i>WarGames</i>): a terminal-style password strength checker. The
 * code display locks in one character at a time like the film's launch-code computer. Nothing typed
 * here is recorded, logged or sent anywhere, and the field is cleared when the window closes.
 */
final class WoprDialog extends JDialog {

    static final String GREETING = "GREETINGS PROFESSOR FALKEN.\n\nSHALL WE PLAY A GAME?";
    private static final Color BACK = Color.BLACK;
    private static final Color TEXT = new Color(0x4dd8ff);
    private static final Color DIM = new Color(0x2a7d99);
    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 14);
    private static final String SCRAMBLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int MAX_LOCK_CHARS = 32;

    private static WoprDialog current;

    final JTextArea greeting = new JTextArea(3, 40);
    final JPasswordField password = new JPasswordField(28);
    final JCheckBox show = new JCheckBox("Show");
    final JLabel code = new JLabel(" ", SwingConstants.CENTER);
    final JLabel rating = new JLabel(" ");
    final JProgressBar meter = new JProgressBar(0, 100);
    final JLabel guesses = new JLabel(" ");
    final JLabel[] times = new JLabel[PasswordStrength.scenarioNames().size()];
    final JLabel warnings = new JLabel(" ");
    private final Random random = new Random();
    private final Timer typing;
    private final Timer locking;
    private final Timer debounce;
    private char[] target = new char[0];
    private int locked;
    private final char echo;

    /** Opens the window, or brings the open one to the front. */
    static void open(Component parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        if (current == null || !current.isDisplayable()) {
            current = new WoprDialog(SwingUtilities.getWindowAncestor(parent));
            current.setLocationRelativeTo(parent);
        }
        current.setVisible(true);
        current.toFront();
        current.password.requestFocusInWindow();
    }

    static WoprDialog current() {
        return current;
    }

    private WoprDialog(Window owner) {
        super(owner, "WOPR", ModalityType.MODELESS);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        echo = password.getEchoChar();

        greeting.setEditable(false);
        greeting.setFocusable(false);
        style(greeting);
        greeting.setFont(MONO.deriveFont(Font.BOLD, 16f));

        style(password);
        password.setCaretColor(TEXT);
        password.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(DIM),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));
        style(show);
        code.setFont(MONO.deriveFont(Font.BOLD, 26f));
        code.setForeground(TEXT);
        code.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(DIM),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));
        style(rating);
        rating.setFont(MONO.deriveFont(Font.BOLD, 16f));
        meter.setStringPainted(false);
        meter.setPreferredSize(new Dimension(200, 12));
        style(guesses);
        style(warnings);
        warnings.setVerticalAlignment(SwingConstants.TOP);

        JPanel entry = row();
        entry.add(prompt("> PASSWORD:"));
        entry.add(password);
        entry.add(show);

        JPanel grid = new JPanel(new GridBagLayout());
        grid.setOpaque(false);
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(2, 0, 2, 16);
        for (int i = 0; i < times.length; i++) {
            c.gridy = i;
            c.gridx = 0;
            c.weightx = 0;
            grid.add(dim(PasswordStrength.scenarioNames().get(i)), c);
            c.gridx = 1;
            c.weightx = 1; // keep the table against the left edge
            times[i] = new JLabel("—");
            style(times[i]);
            grid.add(times[i], c);
        }

        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(BACK);
        body.setBorder(BorderFactory.createEmptyBorder(16, 18, 12, 18));
        for (JComponent comp : new JComponent[]{greeting, gap(), entry, gap(), code, gap(), rating, meter, guesses, gap(),
                dim("TIME TO CRACK (AVERAGE):"), grid, gap(), warnings}) {
            comp.setAlignmentX(LEFT_ALIGNMENT);
            body.add(comp);
        }
        code.setMaximumSize(new Dimension(Integer.MAX_VALUE, 56));
        meter.setMaximumSize(new Dimension(Integer.MAX_VALUE, 12));
        JLabel note = dim("<html>Nothing typed here is saved, logged or sent anywhere. "
                + "Estimates assume the attacker tries common passwords and patterns first.</html>");
        note.setBorder(BorderFactory.createEmptyBorder(8, 18, 10, 18));
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BACK);
        JPanel top = new JPanel(new BorderLayout()); // keeps the rows at their natural height
        top.setBackground(BACK);
        top.add(body, BorderLayout.NORTH);
        root.add(top, BorderLayout.CENTER);
        root.add(note, BorderLayout.SOUTH);
        setContentPane(root);
        setSize(760, 660);

        typing = new Timer(35, null);
        int[] n = {0};
        typing.addActionListener(e -> {
            n[0]++;
            greeting.setText(GREETING.substring(0, Math.min(n[0], GREETING.length())));
            if (n[0] >= GREETING.length()) {
                typing.stop();
            }
        });
        locking = new Timer(70, e -> lockStep());
        debounce = new Timer(250, e -> evaluate());
        debounce.setRepeats(false);

        password.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { debounce.restart(); }
            public void removeUpdate(DocumentEvent e) { debounce.restart(); }
            public void changedUpdate(DocumentEvent e) { }
        });
        show.addActionListener(e -> {
            password.setEchoChar(show.isSelected() ? (char) 0 : echo);
            evaluate();
        });
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                typing.stop();
                locking.stop();
                debounce.stop();
                password.setText("");
                Arrays.fill(target, '\0');
            }
        });
        evaluate();
        typing.start();
    }

    /** Scores the password and restarts the lock-in display. Package-private for the UI driver. */
    void evaluate() {
        char[] pw = password.getPassword();
        try {
            Result r = PasswordStrength.estimate(new String(pw));
            boolean empty = pw.length == 0;
            rating.setText(empty ? "> AWAITING INPUT" : "> STRENGTH: " + r.rating().label().toUpperCase());
            rating.setForeground(empty ? DIM : color(r.rating()));
            meter.setValue(empty ? 0 : (int) Math.min(100, r.bits()));
            meter.setForeground(color(r.rating()));
            guesses.setText(empty ? " " : String.format("ABOUT 2^%.0f GUESSES (%.0f BITS)", r.bits(), r.bits()));
            for (int i = 0; i < times.length; i++) {
                times[i].setText(empty ? "—" : r.crackTimes().get(i).display());
            }
            StringBuilder w = new StringBuilder("<html><div style='width:640px'>");
            if (!empty && new String(pw).equalsIgnoreCase("joshua")) {
                w.append("<b>BACKDOOR FOUND.</b> A strange game: the only winning move is not to use it.<br><br>");
            }
            if (!empty) {
                for (String s : r.warnings()) {
                    w.append("• ").append(escape(s)).append("<br>");
                }
            }
            warnings.setText(w.append("</div></html>").toString());

            Arrays.fill(target, '\0');
            target = Arrays.copyOf(pw, Math.min(pw.length, MAX_LOCK_CHARS));
            locked = 0;
            // One character locks per tick, the whole code within about a second and a half.
            locking.setDelay(Math.max(40, Math.min(140, 1500 / Math.max(1, target.length))));
            lockStep();
            locking.restart();
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private void lockStep() {
        if (target.length == 0) {
            code.setText(" ");
            locking.stop();
            return;
        }
        locked++;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < target.length; i++) {
            char real = show.isSelected() ? target[i] : '•';
            sb.append(i < locked ? real : SCRAMBLE.charAt(random.nextInt(SCRAMBLE.length())));
        }
        if (target.length < password.getDocument().getLength()) {
            sb.append('…');
        }
        code.setText(sb.toString());
        if (locked >= target.length) {
            locking.stop();
        }
    }

    private static Color color(Rating r) {
        return switch (r) {
            case VERY_WEAK -> new Color(0xff4d4d);
            case WEAK -> new Color(0xff9f43);
            case FAIR -> new Color(0xffe066);
            case STRONG -> new Color(0x7dff7a);
            case VERY_STRONG -> new Color(0x39ff14);
        };
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static void style(JComponent c) {
        c.setBackground(BACK);
        c.setForeground(TEXT);
        c.setFont(MONO);
        if (c instanceof JCheckBox) {
            c.setOpaque(false);
        }
    }

    private static JLabel prompt(String text) {
        JLabel l = new JLabel(text);
        style(l);
        return l;
    }

    private static JLabel dim(String text) {
        JLabel l = new JLabel(text);
        style(l);
        l.setForeground(DIM);
        return l;
    }

    private static JPanel row() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.setOpaque(false);
        return p;
    }

    private static JComponent gap() {
        return (JComponent) Box.createVerticalStrut(12);
    }
}
