package com.ourgiant.crypt;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.AWTEventListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.util.Random;

/**
 * The "setec astronomy" egg (a nod to <i>Sneakers</i>): decrypted output resolves letter by
 * letter out of random characters.
 *
 * <p>Only the drawing is scrambled. The text component already holds the real text the whole
 * time, so code that reads it back, Copy, and history all see the exact output. The real text is
 * drawn invisibly and a highlight painter draws the scrambled frame in its place; any key press
 * or click ends the animation at once.
 */
final class TextReveal {

    static final int DURATION_MS = 1100;
    static final int MAX_CHARS = 4000;
    private static final int FRAME_MS = 33;
    private static final String GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#$%&*+=?@";
    private static final String ACTIVE = "codesSwitcher.textReveal";

    private TextReveal() {
    }

    /** Plays the reveal on {@code t} if the egg is on; call it right after setting the output text. */
    static void play(JTextComponent t) {
        if (!EasterEggs.isOn(EasterEggs.Egg.SETEC) || GraphicsEnvironment.isHeadless()) {
            return;
        }
        String text = t.getText();
        if (text.isEmpty() || text.length() > MAX_CHARS || !t.isShowing()) {
            return;
        }
        Object old = t.getClientProperty(ACTIVE);
        if (old instanceof Animation a) {
            a.finish();
        }
        new Animation(t, text).start();
    }

    /**
     * When each character settles, as a fraction of the duration: roughly left to right with some
     * jitter, so it reads like a decryption sweeping across the text.
     */
    static double[] revealTimes(int length, Random random) {
        double[] at = new double[length];
        for (int i = 0; i < length; i++) {
            at[i] = 0.7 * i / Math.max(1, length - 1) + 0.3 * random.nextDouble();
        }
        return at;
    }

    /** One frame: settled characters are real, the rest random; whitespace never changes, so lines don't move. */
    static String frame(String text, double[] revealAt, double progress, Random random) {
        return frame(text, revealAt, progress, random, GLYPHS);
    }

    static String frame(String text, double[] revealAt, double progress, Random random, String glyphs) {
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            sb.append(Character.isWhitespace(c) || progress >= revealAt[i] ? c : glyphs.charAt(random.nextInt(glyphs.length())));
        }
        return sb.toString();
    }

    private static final class Animation implements Highlighter.HighlightPainter {
        private final JTextComponent t;
        private final String text;
        private final Random random = new Random();
        private final double[] revealAt;
        private final Color foreground;
        private final Timer timer;
        private final AWTEventListener stopOnInput = e -> {
            if (e.getID() == KeyEvent.KEY_PRESSED || e.getID() == MouseEvent.MOUSE_PRESSED) {
                finish();
            }
        };
        private final long started = System.currentTimeMillis();
        private Object tag;
        private String current;
        private Rectangle2D[] boxes;

        Animation(JTextComponent t, String text) {
            this.t = t;
            this.text = text;
            this.revealAt = revealTimes(text.length(), random);
            this.foreground = t.getForeground();
            this.current = frame(text, revealAt, 0, random);
            this.timer = new Timer(FRAME_MS, e -> tick());
        }

        void start() {
            try {
                tag = t.getHighlighter().addHighlight(0, text.length(), this);
            } catch (BadLocationException e) {
                return;
            }
            t.putClientProperty(ACTIVE, this);
            t.setForeground(new Color(0, 0, 0, 0));
            Toolkit.getDefaultToolkit().addAWTEventListener(stopOnInput, AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK);
            timer.start();
        }

        private void tick() {
            double progress = (System.currentTimeMillis() - started) / (double) DURATION_MS;
            if (progress >= 1 || !t.isShowing() || !text.equals(t.getText())) {
                finish();
                return;
            }
            current = frame(text, revealAt, progress, random);
            t.repaint();
        }

        void finish() {
            if (t.getClientProperty(ACTIVE) != this) {
                return;
            }
            timer.stop();
            Toolkit.getDefaultToolkit().removeAWTEventListener(stopOnInput);
            t.putClientProperty(ACTIVE, null);
            if (tag != null) {
                t.getHighlighter().removeHighlight(tag);
            }
            t.setForeground(foreground);
            t.repaint();
        }

        @Override
        public void paint(Graphics g, int p0, int p1, Shape bounds, JTextComponent c) {
            if (boxes == null || boxes.length != text.length()) {
                boxes = new Rectangle2D[text.length()];
                for (int i = 0; i < text.length(); i++) {
                    try {
                        boxes[i] = c.modelToView2D(i);
                    } catch (BadLocationException e) {
                        boxes[i] = null;
                    }
                }
            }
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                g2.setFont(c.getFont());
                g2.setColor(foreground);
                FontMetrics fm = g2.getFontMetrics();
                Rectangle clip = g2.getClipBounds();
                for (int i = 0; i < current.length(); i++) {
                    char ch = current.charAt(i);
                    Rectangle2D r = boxes[i];
                    if (r == null || Character.isWhitespace(ch) || (clip != null && !clip.intersects(r.getX(), r.getY(), 40, r.getHeight()))) {
                        continue;
                    }
                    g2.drawString(String.valueOf(ch), (float) r.getX(), (float) (r.getY() + fm.getAscent()));
                }
            } finally {
                g2.dispose();
            }
        }
    }
}
