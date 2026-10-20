package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.HmacGenerator;
import com.ourgiant.crypt.crypto.HmacGenerator.Algorithm;
import com.ourgiant.crypt.crypto.HmacGenerator.KeyFormat;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/** Encoder/Decoder tab that computes an HMAC of a message, shown as hex, Base64 and Base64URL. */
public class HmacPanel extends JPanel {

    private final JComboBox<Algorithm> algorithmBox = new JComboBox<>(Algorithm.values());
    private final JComboBox<KeyFormat> keyFormatBox = new JComboBox<>(KeyFormat.values());
    private final JTextField keyField = new JTextField(28);
    private final JTextArea messageArea = new JTextArea(10, 40);
    private final JTextField hexOut = readOnlyField();
    private final JTextField base64Out = readOnlyField();
    private final JTextField base64UrlOut = readOnlyField();
    private final JTextField expectedField = new JTextField(40);
    private final JLabel matchLabel = new JLabel(" ");

    public HmacPanel() {
        super(new BorderLayout(10, 10));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(new JLabel("Algorithm:"));
        controls.add(algorithmBox);
        controls.add(new JLabel("Key:"));
        controls.add(keyField);
        controls.add(keyFormatBox);
        controls.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

        messageArea.setLineWrap(true);
        messageArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel messagePanel = new JPanel(new BorderLayout());
        messagePanel.setBorder(new TitledBorder("Message (UTF-8)"));
        messagePanel.add(new JScrollPane(messageArea), BorderLayout.CENTER);

        JPanel results = new JPanel(new GridBagLayout());
        results.setBorder(new TitledBorder("HMAC"));
        addRow(results, 0, "Hex:", hexOut);
        addRow(results, 1, "Base64:", base64Out);
        addRow(results, 2, "Base64URL:", base64UrlOut);
        expectedField.setToolTipText("Paste an expected HMAC (hex, Base64 or Base64URL) to compare");
        addRow(results, 3, "Expected:", expectedField);
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1;
        c.gridy = 4;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(2, 4, 2, 4);
        results.add(matchLabel, c);

        JPanel center = new JPanel(new BorderLayout(10, 10));
        center.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        center.add(messagePanel, BorderLayout.CENTER);
        center.add(results, BorderLayout.SOUTH);

        JButton compute = new JButton("Compute HMAC");
        JButton clear = new JButton("Clear All");
        styleButton(compute, new Color(76, 175, 80));
        styleButton(clear, new Color(244, 67, 54));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        buttons.add(compute);
        buttons.add(clear);

        add(controls, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        compute.addActionListener(e -> compute());
        clear.addActionListener(e -> {
            messageArea.setText("");
            keyField.setText("");
            expectedField.setText("");
            hexOut.setText("");
            base64Out.setText("");
            base64UrlOut.setText("");
            matchLabel.setText(" ");
        });
        expectedField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateMatch(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateMatch(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateMatch(); }
        });
    }

    private void compute() {
        try {
            HmacGenerator.Result r = HmacGenerator.compute(messageArea.getText(), keyField.getText(),
                    (KeyFormat) keyFormatBox.getSelectedItem(), (Algorithm) algorithmBox.getSelectedItem());
            hexOut.setText(r.hex());
            base64Out.setText(r.base64());
            base64UrlOut.setText(r.base64Url());
            updateMatch();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "HMAC failed: " + ex.getMessage(), "Error",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void updateMatch() {
        String expected = expectedField.getText().trim();
        if (expected.isEmpty() || hexOut.getText().isEmpty()) {
            matchLabel.setText(" ");
            return;
        }
        String noPad = expected.replaceAll("=+$", "");
        boolean match = expected.equalsIgnoreCase(hexOut.getText())
                || noPad.equals(base64Out.getText().replaceAll("=+$", ""))
                || noPad.equals(base64UrlOut.getText());
        matchLabel.setText(match ? "✔ Matches" : "✘ Does not match");
        matchLabel.setForeground(match ? new Color(46, 125, 50) : new Color(198, 40, 40));
    }

    private static void addRow(JPanel panel, int row, String label, JTextField field) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = row;
        c.insets = new Insets(2, 4, 2, 4);
        c.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, c);
        if (!field.isEditable()) {
            JButton copy = new JButton("Copy");
            copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(field.getText()), null));
            c.gridx = 2;
            c.weightx = 0;
            c.fill = GridBagConstraints.NONE;
            panel.add(copy, c);
        }
    }

    private static JTextField readOnlyField() {
        JTextField f = new JTextField(40);
        f.setEditable(false);
        f.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return f;
    }

    private static void styleButton(JButton button, Color color) {
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setFont(new Font("Arial", Font.BOLD, 12));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }
}
