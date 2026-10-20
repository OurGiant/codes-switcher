package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.PasswordCipher;
import com.ourgiant.crypt.crypto.PasswordCipher.Algorithm;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

/**
 * Encoder/Decoder tab for password-based AES-256-GCM / ChaCha20-Poly1305.
 * Key derivation is deliberately slow, so work runs off the event thread.
 */
public class ModernCipherPanel extends JPanel {

    private final PasswordCipher cipher = new PasswordCipher();

    private final JComboBox<Algorithm> algorithmBox = new JComboBox<>(Algorithm.values());
    private final JPasswordField passwordField = new JPasswordField(24);
    private final JCheckBox showPassword = new JCheckBox("Show");
    private final JTextArea inputArea = textArea(true);
    private final JTextArea outputArea = textArea(false);
    private final JButton encryptButton = new JButton("Encrypt");
    private final JButton decryptButton = new JButton("Decrypt");
    private final JButton copyButton = new JButton("Copy Output");
    private final JButton clearButton = new JButton("Clear All");
    private final JLabel status = new JLabel(" ");

    public ModernCipherPanel() {
        super(new BorderLayout(10, 10));

        algorithmBox.setToolTipText("Used when encrypting. Decryption reads the algorithm from the data.");
        passwordField.setToolTipText("The key is derived from this password with PBKDF2-HMAC-SHA256 ("
                + PasswordCipher.DEFAULT_ITERATIONS + " iterations).");
        char echo = passwordField.getEchoChar();
        showPassword.addActionListener(e -> passwordField.setEchoChar(showPassword.isSelected() ? 0 : echo));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(new JLabel("Algorithm:"));
        controls.add(algorithmBox);
        controls.add(new JLabel("Password:"));
        controls.add(passwordField);
        controls.add(showPassword);
        controls.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

        JPanel center = new JPanel(new GridLayout(2, 1, 10, 10));
        center.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        center.add(titled("Input (plaintext to encrypt, or Base64 to decrypt)", inputArea));
        center.add(titled("Output", outputArea));

        styleButton(encryptButton, new Color(76, 175, 80));
        styleButton(decryptButton, new Color(33, 150, 243));
        styleButton(copyButton, new Color(156, 39, 176));
        styleButton(clearButton, new Color(244, 67, 54));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        buttons.add(encryptButton);
        buttons.add(decryptButton);
        buttons.add(copyButton);
        buttons.add(clearButton);

        JPanel south = new JPanel(new BorderLayout());
        south.add(buttons, BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(0, 12, 8, 12));
        south.add(status, BorderLayout.SOUTH);

        add(controls, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        encryptButton.addActionListener(e -> run(true));
        decryptButton.addActionListener(e -> run(false));
        copyButton.addActionListener(e -> copyOutput());
        clearButton.addActionListener(e -> {
            inputArea.setText("");
            outputArea.setText("");
            status.setText(" ");
            inputArea.requestFocusInWindow();
        });
    }

    private void run(boolean encrypt) {
        String input = inputArea.getText();
        if (input.isEmpty()) {
            message("Please enter text to " + (encrypt ? "encrypt." : "decrypt."), "Input Required");
            return;
        }
        char[] password = passwordField.getPassword();
        if (password.length == 0) {
            message("Please enter a password.", "Password Required");
            return;
        }
        Algorithm algorithm = (Algorithm) algorithmBox.getSelectedItem();

        setBusy(true, encrypt ? "Encrypting…" : "Decrypting…");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                try {
                    return encrypt
                            ? cipher.encrypt(input, password, algorithm)
                            : cipher.decrypt(input, password);
                } finally {
                    Arrays.fill(password, '\0');
                }
            }

            @Override
            protected void done() {
                setBusy(false, " ");
                try {
                    String result = get();
                    outputArea.setText(result);
                    outputArea.setCaretPosition(0);
                    // The password is never recorded; restoring brings back the text and algorithm.
                    SessionHistory.global().record("AES / ChaCha20",
                            (encrypt ? "Encrypt · " + algorithm.displayName() : "Decrypt"), input, result, () -> {
                                algorithmBox.setSelectedItem(algorithm);
                                inputArea.setText(input);
                                outputArea.setText("");
                            });
                    if (!encrypt) {
                        status.setText("Decrypted with " + PasswordCipher.algorithmOf(input).displayName()
                                + " — integrity verified.");
                    } else {
                        status.setText("Encrypted with " + algorithm.displayName() + ".");
                    }
                } catch (ExecutionException ex) {
                    Throwable cause = ex.getCause();
                    outputArea.setText("");
                    message((encrypt ? "Encryption" : "Decryption") + " failed: " + cause.getMessage(), "Error");
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    private void setBusy(boolean busy, String text) {
        encryptButton.setEnabled(!busy);
        decryptButton.setEnabled(!busy);
        status.setText(text);
        setCursor(busy ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : null);
    }

    private void copyOutput() {
        if (outputArea.getText().isEmpty()) {
            message("No output to copy.", "Nothing to Copy");
            return;
        }
        outputArea.selectAll();
        outputArea.copy();
        outputArea.setCaretPosition(0);
        status.setText("Output copied to clipboard.");
    }

    private void message(String text, String title) {
        JOptionPane.showMessageDialog(this, text, title, JOptionPane.INFORMATION_MESSAGE);
    }

    private static JTextArea textArea(boolean editable) {
        JTextArea area = new JTextArea(10, 40);
        area.setLineWrap(true);
        area.setWrapStyleWord(!editable);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setEditable(editable);
        return area;
    }

    private static JPanel titled(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
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
