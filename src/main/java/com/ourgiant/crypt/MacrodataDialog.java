package com.ourgiant.crypt;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

/**
 * The "macrodata refinement" egg (a nod to <i>Severance</i>): a retro terminal of drifting digits.
 * The scary ones twitch as the cursor nears; click a group, then a bin, to refine it.
 */
final class MacrodataDialog extends JDialog {

    static final int COLS = 44;
    static final int ROWS = 16;
    static final int CLUSTERS = 14;
    private static final Color BACK = new Color(0x08131f);
    private static final Color DIGIT = new Color(0x9fdcf5);
    private static final Color DIM = new Color(0x3f6f88);
    private static final Color BRIGHT = new Color(0xe9f9ff);
    private static final Font MONO = new Font(Font.MONOSPACED, Font.BOLD, 17);

    private static MacrodataDialog current;

    final Grid grid = new Grid();
    final JLabel title = new JLabel();
    final JLabel percent = new JLabel();
    final JLabel status = new JLabel(" ");
    final JButton newFile = new JButton("New File");
    MacrodataFile file;
    MacrodataFile.Cluster selected;
    private final Random random = new Random();
    private final Timer timer;
    private final List<Flight> flights = new ArrayList<>();

    /** Digits travelling from the grid into a bin. */
    private record Flight(int digit, Point2D.Double from, int bin, long start) {
    }

    static void open(Component parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        if (current == null || !current.isDisplayable()) {
            current = new MacrodataDialog(SwingUtilities.getWindowAncestor(parent));
            current.setLocationRelativeTo(parent);
        }
        current.setVisible(true);
        current.toFront();
    }

    static MacrodataDialog current() {
        return current;
    }

    private MacrodataDialog(Window owner) {
        super(owner, "Macrodata Refinement", ModalityType.MODELESS);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        title.setFont(MONO.deriveFont(20f));
        title.setForeground(BRIGHT);
        percent.setFont(MONO.deriveFont(20f));
        percent.setForeground(BRIGHT);
        status.setFont(MONO.deriveFont(Font.PLAIN, 13f));
        status.setForeground(DIM);
        newFile.addActionListener(e -> newFile());

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BACK);
        header.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(10, 12, 6, 12),
                BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(DIGIT, 2),
                        BorderFactory.createEmptyBorder(6, 12, 6, 12))));
        header.add(title, BorderLayout.WEST);
        header.add(percent, BorderLayout.EAST);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(BACK);
        footer.setBorder(BorderFactory.createEmptyBorder(4, 12, 10, 12));
        footer.add(status, BorderLayout.CENTER);
        footer.add(newFile, BorderLayout.EAST);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BACK);
        root.add(header, BorderLayout.NORTH);
        root.add(grid, BorderLayout.CENTER);
        root.add(footer, BorderLayout.SOUTH);
        setContentPane(root);
        setSize(980, 700);

        timer = new Timer(40, e -> grid.repaint());
        timer.start();
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                timer.stop();
            }
        });
        newFile();
    }

    void newFile() {
        file = new MacrodataFile(COLS, ROWS, CLUSTERS, random);
        selected = null;
        flights.clear();
        title.setText(file.name);
        updateProgress();
        status.setText("Find the numbers that feel scary. Click a group, then a bin.");
        grid.repaint();
    }

    /** Selects the scary group on a grid cell. Package-private for the UI driver. */
    boolean select(int c, int r) {
        Optional<MacrodataFile.Cluster> k = file.clusterAt(c, r);
        selected = k.orElse(null);
        status.setText(selected == null ? "Those numbers aren't scary. Keep looking."
                : "Selected " + selected.cells.size() + " numbers. Choose a bin.");
        return selected != null;
    }

    /** Refines the selected group into a bin. Package-private for the UI driver. */
    boolean refineInto(int bin) {
        if (selected == null) {
            status.setText("Select some scary numbers first.");
            return false;
        }
        long now = System.currentTimeMillis();
        for (int[] cell : selected.cells) {
            flights.add(new Flight(file.digit(cell[0], cell[1]), grid.center(cell[0], cell[1]), bin, now));
        }
        file.refine(selected, bin);
        selected = null;
        updateProgress();
        if (file.isComplete()) {
            status.setText("File complete. The work is mysterious and important.");
        } else {
            status.setText("Refined into bin 0" + (bin + 1) + ". Keep going.");
        }
        return true;
    }

    private void updateProgress() {
        percent.setText(file.percentComplete() + "% Complete");
    }

    /** The digit field and the five bins under it. */
    final class Grid extends JComponent {
        private Point mouse;

        Grid() {
            setOpaque(true);
            MouseAdapter m = new MouseAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) {
                    mouse = e.getPoint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    mouse = null;
                }

                @Override
                public void mousePressed(MouseEvent e) {
                    int bin = binAt(e.getPoint());
                    if (bin >= 0) {
                        refineInto(bin);
                        return;
                    }
                    int[] cell = cellAt(e.getPoint());
                    if (cell != null) {
                        select(cell[0], cell[1]);
                    }
                }
            };
            addMouseListener(m);
            addMouseMotionListener(m);
        }

        private double cellW() {
            return (getWidth() - 40) / (double) COLS;
        }

        private double cellH() {
            return (fieldBottom() - 16) / (double) ROWS;
        }

        private int fieldBottom() {
            return getHeight() - 110;
        }

        Point2D.Double center(int c, int r) {
            return new Point2D.Double(20 + (c + 0.5) * cellW(), 8 + (r + 0.5) * cellH());
        }

        int[] cellAt(Point p) {
            int c = (int) Math.floor((p.x - 20) / cellW());
            int r = (int) Math.floor((p.y - 8) / cellH());
            return c >= 0 && r >= 0 && c < COLS && r < ROWS ? new int[]{c, r} : null;
        }

        Rectangle binBox(int bin) {
            int w = (getWidth() - 40 - 4 * 16) / MacrodataFile.BINS;
            return new Rectangle(20 + bin * (w + 16), fieldBottom() + 14, w, 84);
        }

        int binAt(Point p) {
            for (int b = 0; b < MacrodataFile.BINS; b++) {
                if (binBox(b).contains(p)) {
                    return b;
                }
            }
            return -1;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                g2.setColor(BACK);
                g2.fillRect(0, 0, getWidth(), getHeight());
                long t = System.currentTimeMillis();
                paintDigits(g2, t);
                paintBins(g2);
                paintFlights(g2, t);
                if (file.isComplete() && flights.isEmpty()) {
                    paintComplete(g2);
                }
            } finally {
                g2.dispose();
            }
        }

        private void paintDigits(Graphics2D g2, long t) {
            for (int c = 0; c < COLS; c++) {
                for (int r = 0; r < ROWS; r++) {
                    if (file.isRefined(c, r)) {
                        continue;
                    }
                    Point2D.Double p = center(c, r);
                    double bob = 2.2 * Math.sin(t / 650.0 + c * 0.7 + r * 1.3);
                    double scale = 1;
                    double dx = 0;
                    double dy = bob;
                    Optional<MacrodataFile.Cluster> k = file.clusterAt(c, r);
                    if (mouse != null) {
                        double d = mouse.distance(p.x, p.y);
                        scale += 1.1 * Math.exp(-(d * d) / (2 * 55.0 * 55.0));
                        if (k.isPresent() && d < 110) {
                            // Scary numbers twitch as the cursor nears.
                            double fear = 1 - d / 110;
                            dx += (random.nextDouble() - 0.5) * 5 * fear;
                            dy += (random.nextDouble() - 0.5) * 5 * fear;
                            scale += 0.35 * fear;
                        }
                    }
                    boolean isSelected = k.isPresent() && k.get() == selected;
                    if (isSelected) {
                        scale += 0.25;
                    }
                    g2.setFont(MONO.deriveFont((float) (MONO.getSize2D() * scale)));
                    g2.setColor(isSelected ? BRIGHT : DIGIT);
                    String s = String.valueOf(file.digit(c, r));
                    FontMetrics fm = g2.getFontMetrics();
                    g2.drawString(s, (float) (p.x + dx - fm.stringWidth(s) / 2.0), (float) (p.y + dy + fm.getAscent() / 2.5));
                }
            }
        }

        private void paintBins(Graphics2D g2) {
            g2.setColor(DIM);
            g2.drawLine(20, fieldBottom() + 4, getWidth() - 20, fieldBottom() + 4);
            for (int b = 0; b < MacrodataFile.BINS; b++) {
                Rectangle box = binBox(b);
                g2.setColor(DIGIT);
                g2.setStroke(new BasicStroke(2f));
                g2.drawRect(box.x, box.y, box.width, 26);
                g2.setFont(MONO.deriveFont(15f));
                String label = "0" + (b + 1);
                g2.drawString(label, box.x + (box.width - g2.getFontMetrics().stringWidth(label)) / 2, box.y + 19);
                for (int i = 0; i < MacrodataFile.TEMPERS.length; i++) {
                    int y = box.y + 34 + i * 13;
                    g2.setFont(MONO.deriveFont(Font.PLAIN, 10f));
                    g2.setColor(DIM);
                    g2.drawString(MacrodataFile.TEMPERS[i], box.x, y + 9);
                    int bx = box.x + 24;
                    int bw = box.width - 24;
                    g2.drawRect(bx, y, bw, 9);
                    g2.setColor(DIGIT);
                    g2.fillRect(bx + 1, y + 1, (int) ((bw - 1) * file.fill(b, i)), 8);
                }
            }
        }

        private void paintFlights(Graphics2D g2, long t) {
            flights.removeIf(f -> t - f.start() > 700);
            for (Flight f : flights) {
                double k = (t - f.start()) / 700.0;
                double e = 1 - Math.pow(1 - k, 3);
                Rectangle box = binBox(f.bin());
                double x = f.from().x + (box.getCenterX() - f.from().x) * e;
                double y = f.from().y + (box.y + 13 - f.from().y) * e;
                g2.setFont(MONO.deriveFont((float) (MONO.getSize2D() * (1 - 0.6 * e))));
                g2.setColor(new Color(BRIGHT.getRed(), BRIGHT.getGreen(), BRIGHT.getBlue(), (int) (255 * (1 - 0.7 * e))));
                g2.drawString(String.valueOf(f.digit()), (float) x, (float) y);
            }
        }

        private void paintComplete(Graphics2D g2) {
            String a = file.name.toUpperCase() + " 100% COMPLETE";
            String b = "Please enjoy each refinement equally.";
            g2.setColor(new Color(8, 19, 31, 220));
            int h = 110;
            int y = fieldBottom() / 2 - h / 2;
            g2.fillRect(60, y, getWidth() - 120, h);
            g2.setColor(BRIGHT);
            g2.setStroke(new BasicStroke(2f));
            g2.drawRect(60, y, getWidth() - 120, h);
            g2.setFont(MONO.deriveFont(26f));
            g2.drawString(a, (getWidth() - g2.getFontMetrics().stringWidth(a)) / 2, y + 48);
            g2.setFont(MONO.deriveFont(Font.PLAIN, 15f));
            g2.setColor(DIGIT);
            g2.drawString(b, (getWidth() - g2.getFontMetrics().stringWidth(b)) / 2, y + 82);
        }
    }
}
