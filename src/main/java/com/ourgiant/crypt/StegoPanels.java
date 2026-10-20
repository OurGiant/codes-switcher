package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.stego.Steganography;
import com.ourgiant.crypt.crypto.stego.Steganography.Payload;
import com.ourgiant.crypt.crypto.stego.StegoAnalysis;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/** The Steganography screens: hide a message in an image, reveal it, and analyze an image for hidden data. */
final class StegoPanels {

    static final String HIDE = "Hide Message";
    static final String REVEAL = "Reveal Message";
    static final String ANALYZE = "Analyze Image";

    private static final Color OK = new Color(46, 125, 50);
    private static final Color WARN = new Color(230, 126, 34);
    private static final Color BAD = new Color(198, 40, 40);

    private StegoPanels() {
    }

    static List<ScreenHost.Screen> create() {
        Steganography stego = new Steganography();
        return List.of(new ScreenHost.Screen(HIDE, new HidePanel(stego)),
                new ScreenHost.Screen(REVEAL, new RevealPanel(stego)),
                new ScreenHost.Screen(ANALYZE, new AnalyzePanel()));
    }

    // ------------------------------------------------------------------ Hide

    static final class HidePanel extends JPanel {
        final JTextField coverField = new JTextField();
        final ImagePreview preview = new ImagePreview("No cover image yet");
        final JLabel capacityLabel = new JLabel(" ");
        final JRadioButton textOption = new JRadioButton("Text", true);
        final JRadioButton fileOption = new JRadioButton("File");
        final JTextArea messageArea = new JTextArea(5, 40);
        final JTextField fileField = new JTextField();
        final JPasswordField password = new JPasswordField();
        final JPasswordField repeat = new JPasswordField();
        final JProgressBar usage = new JProgressBar(0, 1000);
        final JButton hideButton = new JButton("Hide and Save as PNG…");
        final JLabel status = new JLabel(" ");
        private final Steganography stego;
        private BufferedImage cover;

        HidePanel(Steganography stego) {
            super(new BorderLayout(10, 10));
            this.stego = stego;
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            messageArea.setLineWrap(true);
            messageArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            messageArea.putClientProperty("JTextField.placeholderText", "The message to hide");
            usage.setStringPainted(true);
            usage.setString("");
            ButtonGroup kind = new ButtonGroup();
            kind.add(textOption);
            kind.add(fileOption);

            Form f = new Form("1. Cover image");
            f.fileRow("Image:", coverField, false, this::loadCover);
            f.row("", capacityLabel);

            JPanel kindRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            kindRow.add(textOption);
            kindRow.add(Box.createHorizontalStrut(12));
            kindRow.add(fileOption);
            Form m = new Form("2. Message");
            m.row("Hide:", kindRow);
            JScrollPane msgScroll = new JScrollPane(messageArea);
            m.wide(msgScroll);
            m.fileRow("File:", fileField, false, this::updateUsage);
            m.row("Uses:", usage);

            Form p = new Form("3. Password");
            p.row("Password:", password);
            p.row("Repeat:", repeat);

            JPanel left = new JPanel();
            left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
            for (JComponent c : new JComponent[]{f, m, p}) {
                c.setAlignmentX(LEFT_ALIGNMENT);
                left.add(c);
            }

            JPanel previewBox = new JPanel(new BorderLayout());
            previewBox.setBorder(new TitledBorder("Preview"));
            previewBox.add(preview, BorderLayout.CENTER);
            previewBox.setPreferredSize(new Dimension(300, 240));

            JPanel center = new JPanel(new BorderLayout(10, 10));
            center.add(left, BorderLayout.CENTER);
            center.add(previewBox, BorderLayout.EAST);

            JLabel note = new JLabel("<html>Share the PNG file as-is. Saving it as JPEG, editing it, or sending it through "
                    + "apps that compress images erases the message. Hiding protects the content with encryption; "
                    + "it doesn't make the image undetectable to specialised analysis.</html>");
            note.setForeground(UIManager.getColor("Label.disabledForeground"));
            JPanel bottom = new JPanel(new BorderLayout(6, 6));
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttons.add(hideButton);
            bottom.add(status, BorderLayout.CENTER);
            bottom.add(buttons, BorderLayout.EAST);
            bottom.add(note, BorderLayout.SOUTH);

            add(center, BorderLayout.CENTER);
            add(bottom, BorderLayout.SOUTH);

            textOption.addActionListener(e -> updateKind());
            fileOption.addActionListener(e -> updateKind());
            messageArea.getDocument().addDocumentListener(onChange(this::updateUsage));
            hideButton.addActionListener(e -> hideMessage());
            updateKind();
        }

        private void updateKind() {
            messageArea.setEnabled(textOption.isSelected());
            fileField.setEnabled(fileOption.isSelected());
            updateUsage();
        }

        void loadCover() {
            String path = coverField.getText().strip();
            if (path.isEmpty()) {
                return;
            }
            run(this, hideButton, status, "Loading image…", () -> readImage(Path.of(path)), img -> {
                cover = img;
                preview.setImage(img, false);
                capacityLabel.setText(String.format("%d × %d · can hide up to %s", img.getWidth(), img.getHeight(),
                        formatSize(Steganography.capacityBytes(img.getWidth(), img.getHeight(), null))));
                status.setText(" ");
                updateUsage();
            });
        }

        private String fileNameForCapacity() {
            return fileOption.isSelected() && !fileField.getText().isBlank()
                    ? Path.of(fileField.getText().strip()).getFileName().toString() : null;
        }

        private long payloadSize() {
            if (textOption.isSelected()) {
                return messageArea.getText().getBytes(StandardCharsets.UTF_8).length;
            }
            try {
                return fileField.getText().isBlank() ? 0 : Files.size(Path.of(fileField.getText().strip()));
            } catch (IOException | RuntimeException e) {
                return 0;
            }
        }

        void updateUsage() {
            if (cover == null) {
                usage.setValue(0);
                usage.setString("Choose a cover image first");
                return;
            }
            long cap = Steganography.capacityBytes(cover.getWidth(), cover.getHeight(), fileNameForCapacity());
            long size = payloadSize();
            usage.setValue(cap == 0 ? 1000 : (int) Math.min(1000, size * 1000 / cap));
            usage.setString(formatSize(size) + " of " + formatSize(cap) + (size > cap ? " — too big for this image" : ""));
            usage.setForeground(size > cap ? BAD : null);
        }

        private void hideMessage() {
            if (cover == null) {
                message(this, "Choose a cover image first.");
                return;
            }
            char[] pw = password.getPassword();
            char[] pw2 = repeat.getPassword();
            try {
                if (pw.length == 0) {
                    message(this, "Enter a password. You'll need it to reveal the message.");
                    return;
                }
                if (!Arrays.equals(pw, pw2)) {
                    message(this, "The passwords don't match.");
                    return;
                }
                Payload payload;
                if (textOption.isSelected()) {
                    if (messageArea.getText().isEmpty()) {
                        message(this, "Type the message to hide.");
                        return;
                    }
                    payload = Payload.text(messageArea.getText());
                } else {
                    Path file = Path.of(fileField.getText().strip());
                    if (fileField.getText().isBlank() || !Files.isRegularFile(file)) {
                        message(this, "Choose the file to hide.");
                        return;
                    }
                    payload = Payload.file(file.getFileName().toString(), Files.readAllBytes(file));
                }
                Path target = chooseOutput();
                if (target == null) {
                    return;
                }
                char[] pwCopy = pw.clone();
                Path coverPath = Path.of(coverField.getText().strip());
                BufferedImage coverImage = cover;
                run(this, hideButton, status, "Encrypting and hiding…", () -> {
                    try {
                        BufferedImage out = stego.hide(coverImage, payload, pwCopy);
                        if (!ImageIO.write(out, "png", target.toFile())) {
                            throw new IOException("PNG writer unavailable");
                        }
                        return out;
                    } finally {
                        Arrays.fill(pwCopy, '\0');
                    }
                }, out -> {
                    status.setForeground(OK);
                    status.setText("✔ Hidden " + formatSize(payload.data().length) + " in " + target.getFileName());
                    SessionHistory.global().record(HIDE,
                            payload.isText() ? "Hide text (" + formatSize(payload.data().length) + ")" : "Hide file " + payload.fileName(),
                            coverPath.toString(), "Saved " + target, () -> {
                                coverField.setText(coverPath.toString());
                                loadCover();
                            });
                });
            } catch (IOException e) {
                message(this, "Couldn't read the file: " + e.getMessage());
            } finally {
                Arrays.fill(pw, '\0');
                Arrays.fill(pw2, '\0');
            }
        }

        private Path chooseOutput() {
            JFileChooser chooser = new JFileChooser();
            String base = Path.of(coverField.getText().strip()).getFileName().toString().replaceFirst("\\.[^.]+$", "");
            File dir = Path.of(coverField.getText().strip()).toAbsolutePath().getParent().toFile();
            chooser.setCurrentDirectory(dir);
            chooser.setSelectedFile(new File(dir, base + "-hidden.png"));
            chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("PNG image (*.png)", "png"));
            if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return null;
            }
            Path target = pngPath(chooser.getSelectedFile().toPath());
            if (Files.exists(target) && JOptionPane.showConfirmDialog(this, target.getFileName() + " already exists. Replace it?",
                    "Confirm", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                return null;
            }
            return target;
        }
    }

    /** Forces a lossless .png name: "photo.jpg" becomes "photo.png", "photo" becomes "photo.png". */
    static Path pngPath(Path chosen) {
        String name = chosen.getFileName().toString();
        if (name.toLowerCase().endsWith(".png")) {
            return chosen;
        }
        String base = name.replaceFirst("(?i)\\.(jpe?g|gif|bmp|webp|tiff?)$", "");
        return chosen.resolveSibling(base + ".png");
    }

    // ------------------------------------------------------------------ Reveal

    static final class RevealPanel extends JPanel {
        final JTextField imageField = new JTextField();
        final JPasswordField password = new JPasswordField();
        final JButton revealButton = new JButton("Reveal");
        final JLabel status = new JLabel(" ");
        final JTextArea resultArea = new JTextArea(8, 40);
        final JButton saveFileButton = new JButton("Save File…");
        final ImagePreview preview = new ImagePreview("No image yet");
        private final Steganography stego;
        private Payload revealed;

        RevealPanel(Steganography stego) {
            super(new BorderLayout(10, 10));
            this.stego = stego;
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            Form f = new Form("Image and password");
            f.fileRow("Image:", imageField, false, this::loadPreview);
            f.row("Password:", password);
            JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            actions.add(revealButton);
            f.row("", actions);
            f.row("", status);

            resultArea.setEditable(false);
            resultArea.setLineWrap(true);
            resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JPanel result = new JPanel(new BorderLayout(6, 6));
            result.setBorder(new TitledBorder("Hidden message"));
            result.add(new JScrollPane(resultArea), BorderLayout.CENTER);
            JPanel fileRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            fileRow.add(saveFileButton);
            result.add(fileRow, BorderLayout.SOUTH);
            saveFileButton.setVisible(false);

            JPanel previewBox = new JPanel(new BorderLayout());
            previewBox.setBorder(new TitledBorder("Preview"));
            previewBox.add(preview, BorderLayout.CENTER);
            previewBox.setPreferredSize(new Dimension(300, 200));

            JPanel top = new JPanel(new BorderLayout(10, 10));
            top.add(f, BorderLayout.CENTER);
            top.add(previewBox, BorderLayout.EAST);
            add(top, BorderLayout.NORTH);
            add(result, BorderLayout.CENTER);

            revealButton.addActionListener(e -> reveal());
            password.addActionListener(e -> reveal());
            saveFileButton.addActionListener(e -> saveFile());
        }

        void loadPreview() {
            String path = imageField.getText().strip();
            if (!path.isEmpty()) {
                run(this, revealButton, status, "Loading image…", () -> readImage(Path.of(path)), img -> {
                    preview.setImage(img, false);
                    status.setText(" ");
                });
            }
        }

        void reveal() {
            String path = imageField.getText().strip();
            char[] pw = password.getPassword();
            if (path.isEmpty() || pw.length == 0) {
                message(this, "Choose an image and enter the password it was hidden with.");
                Arrays.fill(pw, '\0');
                return;
            }
            revealed = null;
            resultArea.setText("");
            saveFileButton.setVisible(false);
            new SwingWorker<Payload, Void>() {
                @Override
                protected Payload doInBackground() throws Exception {
                    try {
                        return stego.reveal(readImage(Path.of(path)), pw);
                    } finally {
                        Arrays.fill(pw, '\0');
                    }
                }

                @Override
                protected void done() {
                    revealButton.setEnabled(true);
                    try {
                        revealed = get();
                        status.setForeground(OK);
                        if (revealed.isText()) {
                            status.setText("✔ Found a hidden message (" + revealed.text().length() + " characters)");
                            resultArea.setText(revealed.text());
                            resultArea.setCaretPosition(0);
                        } else {
                            status.setText("✔ Found a hidden file: " + revealed.fileName() + " (" + formatSize(revealed.data().length) + ")");
                            resultArea.setText("Hidden file: " + revealed.fileName() + "\nSize: " + formatSize(revealed.data().length)
                                    + "\n\nUse Save File… to write it to disk.");
                            saveFileButton.setVisible(true);
                        }
                        SessionHistory.global().record(REVEAL, "Reveal", path,
                                revealed.isText() ? "Text, " + revealed.text().length() + " characters (not stored here)"
                                        : "File " + revealed.fileName() + ", " + formatSize(revealed.data().length),
                                () -> {
                                    imageField.setText(path);
                                    loadPreview();
                                });
                    } catch (ExecutionException e) {
                        Throwable c = e.getCause();
                        status.setForeground(c instanceof Steganography.NotFoundException ? WARN : BAD);
                        status.setText((c instanceof Steganography.NotFoundException ? "? " : "✘ ") + c.getMessage());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }.execute();
            revealButton.setEnabled(false);
            status.setForeground(UIManager.getColor("Label.foreground"));
            status.setText("Looking for a hidden message…");
        }

        private void saveFile() {
            if (revealed == null || revealed.isText()) {
                return;
            }
            JFileChooser chooser = new JFileChooser();
            File dir = Path.of(imageField.getText().strip()).toAbsolutePath().getParent().toFile();
            chooser.setCurrentDirectory(dir);
            chooser.setSelectedFile(new File(dir, revealed.fileName()));
            if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            Path target = chooser.getSelectedFile().toPath();
            if (Files.exists(target) && JOptionPane.showConfirmDialog(this, target.getFileName() + " already exists. Replace it?",
                    "Confirm", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                return;
            }
            try {
                Files.write(target, revealed.data());
                status.setForeground(OK);
                status.setText("✔ Saved " + target.getFileName());
            } catch (IOException e) {
                message(this, "Couldn't save: " + e.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------ Analyze

    static final class AnalyzePanel extends JPanel {
        final JTextField imageField = new JTextField();
        final JButton analyzeButton = new JButton("Analyze");
        final JLabel status = new JLabel(" ");
        final ImagePreview original = new ImagePreview("Original");
        final ImagePreview plane = new ImagePreview("Lowest-bit plane");
        final JTextArea report = new JTextArea(9, 40);

        AnalyzePanel() {
            super(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            Form f = new Form("Image");
            f.fileRow("Image:", imageField, false, this::analyze);
            JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            actions.add(analyzeButton);
            f.row("", actions);
            f.row("", status);

            JPanel images = new JPanel(new GridLayout(1, 2, 10, 10));
            images.add(titled("Original", original));
            images.add(titled("Lowest bit of each colour", plane));

            report.setEditable(false);
            report.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JPanel center = new JPanel(new BorderLayout(10, 10));
            center.add(images, BorderLayout.CENTER);
            center.add(titled("Statistics", new JScrollPane(report)), BorderLayout.SOUTH);

            add(f, BorderLayout.NORTH);
            add(center, BorderLayout.CENTER);
            analyzeButton.addActionListener(e -> analyze());
        }

        record Result(BufferedImage img, BufferedImage plane, StegoAnalysis.Report report) {
        }

        void analyze() {
            String path = imageField.getText().strip();
            if (path.isEmpty()) {
                message(this, "Choose an image to analyze.");
                return;
            }
            run(this, analyzeButton, status, "Analyzing…", () -> {
                BufferedImage img = readImage(Path.of(path));
                return new Result(img, StegoAnalysis.lsbPlane(img), StegoAnalysis.analyze(img));
            }, r -> {
                original.setImage(r.img(), false);
                plane.setImage(r.plane(), true);
                report.setText(format(r.report()));
                report.setCaretPosition(0);
                double p = r.report().maxProbability();
                status.setForeground(p > 0.9 ? BAD : p > 0.5 ? WARN : OK);
                status.setText(p > 0.9 ? "✘ Strong sign of LSB-hidden data"
                        : p > 0.5 ? "⚠ Some sign of LSB-hidden data"
                        : "✔ No obvious sign of LSB-hidden data (small or scattered payloads can still be present)");
                SessionHistory.global().record(ANALYZE, "Analyze", path, report.getText(), () -> {
                    imageField.setText(path);
                    analyze();
                });
            });
        }

        static String format(StegoAnalysis.Report r) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Size: %d × %d%n%n", r.width(), r.height()));
            sb.append("Channel   1-bits   Chi-square embedding probability\n");
            for (StegoAnalysis.ChannelStats c : List.of(r.red(), r.green(), r.blue())) {
                sb.append(String.format("%-8s  %5.1f%%   %5.1f%%%n", c.channel(), c.onesRatio() * 100, c.embeddingProbability() * 100));
            }
            sb.append(String.format("Top 10%% of rows (sequential embedding): %5.1f%%%n%n", r.topRegionProbability() * 100));
            sb.append("Lowest-bit plane: fine noise or flat areas are normal; shapes, bands or a sharp edge\n");
            sb.append("between noisy and smooth regions suggest something was written there.\n");
            sb.append("The chi-square test reliably spots data written into most of an image or from the top down.\n");
            sb.append("It is weak against small payloads scattered across the image, such as this app's own output.");
            return sb.toString();
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Reads PNG/BMP/JPEG/GIF; anything else is a clear error, not a null image. */
    static BufferedImage readImage(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("File not found: " + path);
        }
        BufferedImage img = ImageIO.read(path.toFile());
        if (img == null) {
            throw new IOException(path.getFileName() + " isn't an image format this app can read (use PNG, BMP, JPEG or GIF)");
        }
        return img;
    }

    /** Scaled preview of an image; LSB planes use nearest-neighbour so their noise stays visible. */
    static final class ImagePreview extends JComponent {
        private final String emptyText;
        private BufferedImage image;
        private boolean pixelated;

        ImagePreview(String emptyText) {
            this.emptyText = emptyText;
            setPreferredSize(new Dimension(280, 180));
        }

        void setImage(BufferedImage img, boolean pixelated) {
            this.image = img;
            this.pixelated = pixelated;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                if (image == null) {
                    g2.setColor(UIManager.getColor("Label.disabledForeground"));
                    FontMetrics fm = g2.getFontMetrics();
                    g2.drawString(emptyText, (getWidth() - fm.stringWidth(emptyText)) / 2, getHeight() / 2);
                    return;
                }
                double scale = Math.min((double) getWidth() / image.getWidth(), (double) getHeight() / image.getHeight());
                scale = Math.min(scale, 1.0);
                int w = (int) (image.getWidth() * scale);
                int h = (int) (image.getHeight() * scale);
                g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, pixelated
                        ? RenderingHints.VALUE_INTERPOLATION_NEAREST_NEIGHBOR : RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                g2.drawImage(image, (getWidth() - w) / 2, (getHeight() - h) / 2, w, h, null);
            } finally {
                g2.dispose();
            }
        }
    }

    private static <T> void run(Component parent, JButton button, JLabel status, String busy, Callable<T> task, Consumer<T> after) {
        button.setEnabled(false);
        status.setForeground(UIManager.getColor("Label.foreground"));
        status.setText(busy);
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return task.call();
            }

            @Override
            protected void done() {
                button.setEnabled(true);
                try {
                    after.accept(get());
                } catch (ExecutionException e) {
                    status.setForeground(BAD);
                    status.setText("✘ " + e.getCause().getMessage());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    private static String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " bytes";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }

    private static DocumentListener onChange(Runnable r) {
        return new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { r.run(); }
            public void removeUpdate(DocumentEvent e) { r.run(); }
            public void changedUpdate(DocumentEvent e) { r.run(); }
        };
    }

    private static JPanel titled(String title, JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private static void message(Component parent, String text) {
        JOptionPane.showMessageDialog(parent, text, "Steganography", JOptionPane.INFORMATION_MESSAGE);
    }

    /** A titled label | field | Browse grid. */
    private static final class Form extends JPanel {
        private int row;

        Form(String title) {
            super(new GridBagLayout());
            setBorder(new TitledBorder(title));
        }

        void row(String label, JComponent field) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 5, 3, 5);
            c.gridy = row++;
            c.anchor = GridBagConstraints.WEST;
            add(new JLabel(label), c);
            c.gridx = 1;
            c.weightx = 1;
            c.gridwidth = 2;
            c.fill = GridBagConstraints.HORIZONTAL;
            add(field, c);
        }

        void wide(JComponent field) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 5, 3, 5);
            c.gridy = row++;
            c.gridx = 1;
            c.gridwidth = 2;
            c.weightx = 1;
            c.weighty = 1;
            c.fill = GridBagConstraints.BOTH;
            add(field, c);
        }

        void fileRow(String label, JTextField field, boolean save, Runnable onChosen) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 5, 3, 5);
            c.gridy = row++;
            c.anchor = GridBagConstraints.WEST;
            add(new JLabel(label), c);
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            add(field, c);
            JButton browse = new JButton("Browse...");
            browse.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser();
                if (!field.getText().isBlank()) {
                    chooser.setSelectedFile(new File(field.getText().strip()));
                }
                if ((save ? chooser.showSaveDialog(this) : chooser.showOpenDialog(this)) == JFileChooser.APPROVE_OPTION) {
                    field.setText(chooser.getSelectedFile().getAbsolutePath());
                    onChosen.run();
                }
            });
            field.addActionListener(e -> onChosen.run()); // Enter, or a dropped file
            c.gridx = 2;
            c.weightx = 0;
            c.fill = GridBagConstraints.NONE;
            add(browse, c);
        }
    }
}
