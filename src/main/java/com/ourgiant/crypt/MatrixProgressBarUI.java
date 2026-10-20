package com.ourgiant.crypt;

import javax.swing.*;
import javax.swing.plaf.ComponentUI;
import javax.swing.plaf.basic.BasicProgressBarUI;
import java.awt.*;
import java.util.Random;

/**
 * The "white rabbit" egg (a nod to <i>The Matrix</i>): progress bars drawn as falling green
 * glyphs, brighter where the bar is filled. The progress text is still drawn on top, so the bar
 * keeps doing its job. Installed for every progress bar through {@link #setEnabled}.
 */
public final class MatrixProgressBarUI extends BasicProgressBarUI {

    private static final String KEY = "ProgressBarUI";
    private static final Color BACK = new Color(0x020a03);
    private static final Color DIM = new Color(0x0f5a1c);
    private static final Color BRIGHT = new Color(0x39ff14);
    private static final Color HEAD = new Color(0xd8ffd0);
    private static final int CELL = 9;

    private static String glyphs;

    private final Random random = new Random();
    private Timer timer;
    private int[] drops = new int[0];
    private char[][] cells = new char[0][0];

    @SuppressWarnings("unused") // called reflectively by UIManager
    public static ComponentUI createUI(JComponent c) {
        return new MatrixProgressBarUI();
    }

    /** Turns the rain on or off for every progress bar, existing and future. */
    static void setEnabled(boolean on) {
        UIManager.put(KEY, on ? MatrixProgressBarUI.class.getName() : null);
        refresh();
    }

    /** After a theme change, which resets component UIs, keep the rain if it's on. */
    static void reapply() {
        if (EasterEggs.isOn(EasterEggs.Egg.RABBIT)) {
            UIManager.put(KEY, MatrixProgressBarUI.class.getName());
        }
    }

    private static void refresh() {
        for (Window w : Window.getWindows()) {
            if (w.isDisplayable()) {
                SwingUtilities.updateComponentTreeUI(w);
            }
        }
    }

    @Override
    public void installUI(JComponent c) {
        super.installUI(c);
        LookAndFeel.installProperty(c, "opaque", true);
        c.setBorder(new javax.swing.plaf.BorderUIResource.LineBorderUIResource(DIM));
        timer = new Timer(70, e -> {
            if (c.isShowing()) {
                step(c);
                c.repaint();
            }
        });
        timer.start();
    }

    @Override
    public void uninstallUI(JComponent c) {
        timer.stop();
        super.uninstallUI(c);
    }

    @Override
    public Dimension getPreferredSize(JComponent c) {
        Dimension d = super.getPreferredSize(c);
        return new Dimension(d.width, Math.max(d.height, 3 * CELL + 2));
    }

    private void step(JComponent c) {
        int cols = Math.max(1, c.getWidth() / CELL);
        int rows = Math.max(1, c.getHeight() / CELL);
        if (drops.length != cols || cells.length == 0 || cells[0].length != rows) {
            drops = new int[cols];
            cells = new char[cols][rows];
            for (int i = 0; i < cols; i++) {
                drops[i] = -random.nextInt(rows * 4 + 1);
                for (int j = 0; j < rows; j++) {
                    cells[i][j] = glyph();
                }
            }
        }
        for (int i = 0; i < cols; i++) {
            drops[i]++;
            if (drops[i] > rows + 4 && random.nextInt(6) == 0) {
                drops[i] = -random.nextInt(rows * 3 + 1);
            }
            if (random.nextInt(5) == 0) {
                cells[i][random.nextInt(rows)] = glyph();
            }
        }
    }

    private char glyph() {
        String g = glyphs;
        if (g == null) {
            // Half-width katakana where the font has them, like the film; digits and letters otherwise.
            Font f = new Font(Font.MONOSPACED, Font.PLAIN, 10);
            g = f.canDisplay('ｱ') ? "ｦｧｨｩｪｱｲｳｴｵｶｷｸｹｺ0123456789Z"
                    : "0123456789ABCDEFZ:=*+<>";
            glyphs = g;
        }
        return g.charAt(random.nextInt(g.length()));
    }

    @Override
    public void paint(Graphics g, JComponent c) {
        JProgressBar bar = (JProgressBar) c;
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            int w = c.getWidth();
            int h = c.getHeight();
            g2.setColor(BACK);
            g2.fillRect(0, 0, w, h);
            if (drops.length == 0) {
                step(c);
            }
            double done = bar.isIndeterminate() ? 1 : bar.getPercentComplete();
            int filledX = (int) Math.round(w * done);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setFont(new Font(Font.MONOSPACED, Font.PLAIN, CELL + 1));
            int ascent = g2.getFontMetrics().getAscent();
            for (int i = 0; i < drops.length; i++) {
                int x = i * CELL;
                boolean filled = x < filledX;
                for (int j = 0; j < cells[i].length; j++) {
                    int age = drops[i] - j; // 0 at the head of the drop, growing up its tail
                    if (age < 0 || age > 5) {
                        continue;
                    }
                    Color base = age == 0 ? HEAD : filled ? BRIGHT : DIM;
                    int alpha = age == 0 ? 255 : Math.max(40, 230 - age * 40);
                    g2.setColor(new Color(base.getRed(), base.getGreen(), base.getBlue(), filled || age == 0 ? alpha : alpha / 2));
                    g2.drawString(String.valueOf(cells[i][j]), x + 1, j * CELL + ascent - 1);
                }
            }
            if (!bar.isIndeterminate() && filledX > 0) {
                g2.setColor(new Color(57, 255, 20, 28));
                g2.fillRect(0, 0, filledX, h);
            }
            if (bar.isStringPainted() && bar.getString() != null && !bar.getString().isEmpty()) {
                g2.setFont(c.getFont());
                FontMetrics fm = g2.getFontMetrics();
                String s = bar.getString();
                int sx = (w - fm.stringWidth(s)) / 2;
                int sy = (h - fm.getHeight()) / 2 + fm.getAscent();
                g2.setColor(Color.BLACK);
                for (int dx = -1; dx <= 1; dx++) {
                    for (int dy = -1; dy <= 1; dy++) {
                        g2.drawString(s, sx + dx, sy + dy);
                    }
                }
                g2.setColor(HEAD);
                g2.drawString(s, sx, sy);
            }
        } finally {
            g2.dispose();
        }
    }
}
