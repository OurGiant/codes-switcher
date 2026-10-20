package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.FileHasher;
import com.ourgiant.crypt.crypto.FileHasher.Algorithm;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

/** Encoder/Decoder tab that hashes a file of any size and checks it against an expected hash. */
public class FileHashPanel extends JPanel {

    private final JTextField fileField = new JTextField(36);
    private final JComboBox<Algorithm> algorithmBox = new JComboBox<>(Algorithm.values());
    private final JTextField resultField = new JTextField(64);
    private final JTextField expectedField = new JTextField(64);
    private final JLabel matchLabel = new JLabel(" ");
    private final JProgressBar progress = new JProgressBar(0, 1000);
    private final JButton computeButton = new JButton("Compute Hash");
    private final JButton cancelButton = new JButton("Cancel");
    private SwingWorker<String, Long> worker;

    public FileHashPanel() {
        super(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        resultField.setEditable(false);
        resultField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        expectedField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        expectedField.setToolTipText("Paste the published hash. \"hash  filename\" and \"SHA256 (file) = hash\" lines work too.");
        progress.setStringPainted(true);
        progress.setString("");
        cancelButton.setEnabled(false);

        JButton browse = new JButton("Browse…");
        JButton copy = new JButton("Copy");

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new TitledBorder("File"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        row(form, c, 0, "File:", fileField, browse);
        row(form, c, 1, "Algorithm:", algorithmBox, null);
        c.gridy = 2;
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        actions.add(computeButton);
        actions.add(Box.createHorizontalStrut(6));
        actions.add(cancelButton);
        form.add(actions, c);
        c.gridy = 3;
        form.add(progress, c);

        JPanel results = new JPanel(new GridBagLayout());
        results.setBorder(new TitledBorder("Result"));
        GridBagConstraints r = new GridBagConstraints();
        r.insets = new Insets(4, 4, 4, 4);
        r.anchor = GridBagConstraints.WEST;
        row(results, r, 0, "Hash:", resultField, copy);
        row(results, r, 1, "Expected:", expectedField, null);
        r.gridy = 2;
        r.gridx = 1;
        results.add(matchLabel, r);

        JPanel stack = new JPanel(new BorderLayout(10, 10));
        stack.add(form, BorderLayout.NORTH);
        stack.add(results, BorderLayout.CENTER);
        add(stack, BorderLayout.NORTH);

        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(chooser.getSelectedFile().getAbsolutePath());
                resultField.setText("");
                updateMatch();
            }
        });
        computeButton.addActionListener(e -> compute());
        cancelButton.addActionListener(e -> {
            if (worker != null) {
                worker.cancel(true);
            }
        });
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(resultField.getText()), null));
        algorithmBox.addActionListener(e -> {
            resultField.setText("");
            updateMatch();
        });
        expectedField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateMatch(); }
            public void removeUpdate(DocumentEvent e) { updateMatch(); }
            public void changedUpdate(DocumentEvent e) { updateMatch(); }
        });
    }

    private void compute() {
        Path file = Path.of(fileField.getText().strip());
        if (fileField.getText().isBlank() || !Files.isRegularFile(file)) {
            JOptionPane.showMessageDialog(this, "Choose a file to hash.", "File Hash", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Algorithm algorithm = (Algorithm) algorithmBox.getSelectedItem();
        long size;
        try {
            size = Files.size(file);
        } catch (java.io.IOException e) {
            JOptionPane.showMessageDialog(this, "Couldn't read the file: " + e.getMessage(), "File Hash",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        resultField.setText("");
        matchLabel.setText(" ");
        computeButton.setEnabled(false);
        cancelButton.setEnabled(true);
        progress.setValue(0);
        progress.setString("Hashing…");

        worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() throws Exception {
                return FileHasher.hash(file, algorithm, bytes -> publish(bytes));
            }

            @Override
            protected void process(List<Long> chunks) {
                long done = chunks.get(chunks.size() - 1);
                progress.setValue(size == 0 ? 1000 : (int) (done * 1000 / size));
                progress.setString(String.format("%,d / %,d bytes", done, size));
            }

            @Override
            protected void done() {
                computeButton.setEnabled(true);
                cancelButton.setEnabled(false);
                try {
                    resultField.setText(get());
                    progress.setValue(1000);
                    progress.setString(String.format("Done — %,d bytes", size));
                    updateMatch();
                } catch (CancellationException e) {
                    progress.setString("Cancelled");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    progress.setString("Failed");
                    JOptionPane.showMessageDialog(FileHashPanel.this, "Hashing failed: " + e.getCause().getMessage(),
                            "File Hash", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void updateMatch() {
        String expected = expectedField.getText();
        if (expected.isBlank()) {
            matchLabel.setText(" ");
            return;
        }
        Algorithm current = (Algorithm) algorithmBox.getSelectedItem();
        List<Algorithm> fits = FileHasher.candidatesFor(expected);
        if (!fits.isEmpty() && !fits.contains(current)) {
            matchLabel.setForeground(new Color(230, 126, 34));
            matchLabel.setText("Expected hash is the length of " + fits.stream().map(Algorithm::toString)
                    .collect(Collectors.joining(" or ")) + ", not " + current + " — change the algorithm?");
            return;
        }
        if (resultField.getText().isEmpty()) {
            matchLabel.setText("Compute the hash to compare.");
            matchLabel.setForeground(UIManager.getColor("Label.foreground"));
            return;
        }
        boolean match = FileHasher.matches(expected, resultField.getText());
        matchLabel.setText(match ? "✔ Matches — the file is intact" : "✘ Does not match");
        matchLabel.setForeground(match ? new Color(46, 125, 50) : new Color(198, 40, 40));
    }

    private static void row(JPanel panel, GridBagConstraints c, int y, String label, JComponent field, JComponent extra) {
        c.gridy = y;
        c.gridx = 0;
        c.weightx = 0;
        c.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, c);
        if (extra != null) {
            c.gridx = 2;
            c.weightx = 0;
            c.fill = GridBagConstraints.NONE;
            panel.add(extra, c);
        }
    }
}
