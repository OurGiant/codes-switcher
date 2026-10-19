package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.BlowfishCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;

import static com.ourgiant.crypt.TextCodec.ASCII85;
import static com.ourgiant.crypt.TextCodec.BASE32;
import static com.ourgiant.crypt.TextCodec.BASE58;
import static com.ourgiant.crypt.TextCodec.BASE64;
import static com.ourgiant.crypt.TextCodec.DEFLATE;
import static com.ourgiant.crypt.TextCodec.GZIP;
import static com.ourgiant.crypt.TextCodec.BINARY;
import static com.ourgiant.crypt.TextCodec.HEX;
import static com.ourgiant.crypt.TextCodec.HTML;
import static com.ourgiant.crypt.TextCodec.JSON;
import static com.ourgiant.crypt.TextCodec.JWT;
import static com.ourgiant.crypt.TextCodec.MD5;
import static com.ourgiant.crypt.TextCodec.ROT13;
import static com.ourgiant.crypt.TextCodec.SHA256;
import static com.ourgiant.crypt.TextCodec.SHA512;
import static com.ourgiant.crypt.TextCodec.UNICODE;
import static com.ourgiant.crypt.TextCodec.URL;

public class EncodingDecodingApp extends JFrame {
    private static final Logger log = LoggerFactory.getLogger(EncodingDecodingApp.class);

    private JComboBox<String> methodComboBox;
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JButton encodeButton;
    private JButton decodeButton;
    private JButton clearButton;
    private JButton copyButton;
    private JButton swapButton;

    // Blowfish tab components
    private JTextField blowfishKeyField;
    private JCheckBox blowfishCrcCheckBox;
    private JTextArea blowfishInputArea;
    private JTextArea blowfishOutputArea;
    private JButton blowfishEncryptButton;
    private JButton blowfishDecryptButton;
    private JButton blowfishClearButton;
    private JButton blowfishCopyButton;

    public EncodingDecodingApp() {
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("Universal Encoder/Decoder v1.0");
        setSize(800, 600);
        setLocationRelativeTo(null);
        setJMenuBar(AppLauncher.createMenuBar(this));

        Image icon = AppLauncher.loadAppIcon();
        if (icon != null) {
            setIconImage(icon);
        }
    }

    private void initializeComponents() {
        // Method selection
        methodComboBox = new JComboBox<>(new String[]{
            BASE64, BASE32, BASE58, ASCII85, URL, HTML, HEX, BINARY, ROT13,
            JSON, UNICODE, GZIP, DEFLATE, JWT, SHA256, SHA512, MD5
        });
        methodComboBox.setSelectedIndex(0);
        
        // Text areas
        inputTextArea = new JTextArea(10, 40);
        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        inputTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        outputTextArea = new JTextArea(10, 40);
        outputTextArea.setLineWrap(true);
        outputTextArea.setWrapStyleWord(true);
        outputTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputTextArea.setEditable(false);
        outputTextArea.setBackground(new Color(245, 245, 245));
        
        // Buttons
        encodeButton = new JButton("Encode");
        decodeButton = new JButton("Decode");
        clearButton = new JButton("Clear All");
        copyButton = new JButton("Copy Output");
        swapButton = new JButton("Swap ↕");
        
        // Style buttons
        styleButton(encodeButton, new Color(76, 175, 80));
        styleButton(decodeButton, new Color(33, 150, 243));
        styleButton(clearButton, new Color(244, 67, 54));
        styleButton(copyButton, new Color(156, 39, 176));
        styleButton(swapButton, new Color(255, 152, 0));

        // Blowfish tab
        blowfishKeyField = new JTextField(24);
        blowfishCrcCheckBox = new JCheckBox("CRC framing", true);
        blowfishCrcCheckBox.setToolTipText(
                "Append and verify an integrity checksum. Must match the setting used when the text was encrypted.");

        blowfishInputArea = new JTextArea(10, 40);
        blowfishInputArea.setLineWrap(true);
        blowfishInputArea.setWrapStyleWord(true);
        blowfishInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        blowfishOutputArea = new JTextArea(10, 40);
        blowfishOutputArea.setLineWrap(true);
        blowfishOutputArea.setWrapStyleWord(true);
        blowfishOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        blowfishOutputArea.setEditable(false);
        blowfishOutputArea.setBackground(new Color(245, 245, 245));

        blowfishEncryptButton = new JButton("Encrypt");
        blowfishDecryptButton = new JButton("Decrypt");
        blowfishClearButton = new JButton("Clear All");
        blowfishCopyButton = new JButton("Copy Output");

        styleButton(blowfishEncryptButton, new Color(76, 175, 80));
        styleButton(blowfishDecryptButton, new Color(33, 150, 243));
        styleButton(blowfishClearButton, new Color(244, 67, 54));
        styleButton(blowfishCopyButton, new Color(156, 39, 176));
    }
    
    private void styleButton(JButton button, Color color) {
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setFont(new Font("Arial", Font.BOLD, 12));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout(10, 10));

        // Top panel with method selection
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("Encoding Method:"));
        topPanel.add(methodComboBox);
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        
        // Center panel with text areas
        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 10, 10));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(new TitledBorder("Input Text"));
        inputPanel.add(new JScrollPane(inputTextArea), BorderLayout.CENTER);
        
        // Output panel
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(new TitledBorder("Output Text"));
        outputPanel.add(new JScrollPane(outputTextArea), BorderLayout.CENTER);
        
        centerPanel.add(inputPanel);
        centerPanel.add(outputPanel);
        
        // Bottom panel with buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        buttonPanel.add(encodeButton);
        buttonPanel.add(decodeButton);
        buttonPanel.add(swapButton);
        buttonPanel.add(copyButton);
        buttonPanel.add(clearButton);
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));

        // Text-codec tab aggregates the existing method/input/output/button panels
        JPanel codecTab = new JPanel(new BorderLayout(10, 10));
        codecTab.add(topPanel, BorderLayout.NORTH);
        codecTab.add(centerPanel, BorderLayout.CENTER);
        codecTab.add(buttonPanel, BorderLayout.SOUTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Text Codecs", codecTab);
        tabs.addTab("Blowfish", buildBlowfishTab());

        add(tabs, BorderLayout.CENTER);
    }

    private JPanel buildBlowfishTab() {
        // Key + CRC controls
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(new JLabel("Key:"));
        controls.add(blowfishKeyField);
        controls.add(blowfishCrcCheckBox);
        controls.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

        JPanel center = new JPanel(new GridLayout(2, 1, 10, 10));
        center.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(new TitledBorder("Input (plaintext to encrypt, or hex to decrypt)"));
        inputPanel.add(new JScrollPane(blowfishInputArea), BorderLayout.CENTER);

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(new TitledBorder("Output"));
        outputPanel.add(new JScrollPane(blowfishOutputArea), BorderLayout.CENTER);

        center.add(inputPanel);
        center.add(outputPanel);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        buttons.add(blowfishEncryptButton);
        buttons.add(blowfishDecryptButton);
        buttons.add(blowfishCopyButton);
        buttons.add(blowfishClearButton);
        buttons.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));

        JPanel tab = new JPanel(new BorderLayout(10, 10));
        tab.add(controls, BorderLayout.NORTH);
        tab.add(center, BorderLayout.CENTER);
        tab.add(buttons, BorderLayout.SOUTH);
        return tab;
    }
    
    private void setupEventHandlers() {
        encodeButton.addActionListener(e -> performEncoding());
        decodeButton.addActionListener(e -> performDecoding());
        clearButton.addActionListener(e -> clearAll());
        copyButton.addActionListener(e -> copyOutput());
        swapButton.addActionListener(e -> swapInputOutput());

        blowfishEncryptButton.addActionListener(e -> performBlowfish(true));
        blowfishDecryptButton.addActionListener(e -> performBlowfish(false));
        blowfishClearButton.addActionListener(e -> clearBlowfish());
        blowfishCopyButton.addActionListener(e -> copyBlowfishOutput());
        
        // Update decode button based on selected method
        methodComboBox.addActionListener(e -> updateDecodeButton());
        updateDecodeButton(); // Initial state
        
        // Allow Enter key to trigger encoding
        inputTextArea.getInputMap().put(KeyStroke.getKeyStroke("ctrl ENTER"), "encode");
        inputTextArea.getActionMap().put("encode", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performEncoding();
            }
        });
    }
    
    private void updateDecodeButton() {
        String method = (String) methodComboBox.getSelectedItem();
        boolean isHashMethod = method.contains("Hash");
        boolean isJWT = method.equals(JWT);
        
        decodeButton.setEnabled(!isHashMethod);
        encodeButton.setEnabled(!isJWT);
        
        if (isHashMethod) {
            decodeButton.setToolTipText("Hash functions are one-way only");
            encodeButton.setToolTipText("Encode the input text");
        } else if (isJWT) {
            decodeButton.setToolTipText("Decode JWT token");
            encodeButton.setToolTipText("JWT encoding not supported - use a JWT library");
        } else {
            decodeButton.setToolTipText("Decode the input text");
            encodeButton.setToolTipText("Encode the input text");
        }
    }
    
    private void performEncoding() {
        String input = inputTextArea.getText();
        if (input.isEmpty()) {
            showMessage("Please enter text to encode.", "Input Required");
            return;
        }
        
        try {
            String encoded = TextCodec.encode(input, (String) methodComboBox.getSelectedItem());
            outputTextArea.setText(encoded);
            outputTextArea.setCaretPosition(0);
        } catch (Exception e) {
            showMessage("Encoding failed: " + e.getMessage(), "Error");
        }
    }
    
    private void performDecoding() {
        String input = inputTextArea.getText();
        if (input.isEmpty()) {
            showMessage("Please enter text to decode.", "Input Required");
            return;
        }
        
        try {
            String decoded = TextCodec.decode(input, (String) methodComboBox.getSelectedItem());
            outputTextArea.setText(decoded);
            outputTextArea.setCaretPosition(0);
        } catch (Exception e) {
            showMessage("Decoding failed: " + e.getMessage(), "Error");
        }
    }
    
    private void clearAll() {
        inputTextArea.setText("");
        outputTextArea.setText("");
        inputTextArea.requestFocus();
    }
    
    private void copyOutput() {
        if (outputTextArea.getText().isEmpty()) {
            showMessage("No output to copy.", "Nothing to Copy");
            return;
        }
        
        outputTextArea.selectAll();
        outputTextArea.copy();
        outputTextArea.setCaretPosition(0);
        showMessage("Output copied to clipboard!", "Copied");
    }
    
    private void swapInputOutput() {
        String input = inputTextArea.getText();
        String output = outputTextArea.getText();
        
        if (output.isEmpty()) {
            showMessage("No output to swap.", "Nothing to Swap");
            return;
        }
        
        inputTextArea.setText(output);
        outputTextArea.setText(input);
    }
    
    private void performBlowfish(boolean encrypt) {
        String input = blowfishInputArea.getText();
        if (input.isEmpty()) {
            showMessage("Please enter text to " + (encrypt ? "encrypt." : "decrypt."), "Input Required");
            return;
        }

        try {
            BlowfishCodec codec = new BlowfishCodec(blowfishKeyField.getText());
            boolean useCrc = blowfishCrcCheckBox.isSelected();
            String result = encrypt ? codec.encrypt(input, useCrc) : codec.decrypt(input, useCrc);

            if (!encrypt && result.isEmpty()) {
                showMessage(
                        "Decryption produced no output. Check that the key and CRC setting match "
                                + "those used to encrypt, and that the input is valid hex.",
                        "Decryption Failed");
            }

            blowfishOutputArea.setText(result);
            blowfishOutputArea.setCaretPosition(0);
        } catch (Exception e) {
            showMessage((encrypt ? "Encryption" : "Decryption") + " failed: " + e.getMessage(), "Error");
        }
    }

    private void clearBlowfish() {
        blowfishInputArea.setText("");
        blowfishOutputArea.setText("");
        blowfishInputArea.requestFocus();
    }

    private void copyBlowfishOutput() {
        if (blowfishOutputArea.getText().isEmpty()) {
            showMessage("No output to copy.", "Nothing to Copy");
            return;
        }
        blowfishOutputArea.selectAll();
        blowfishOutputArea.copy();
        blowfishOutputArea.setCaretPosition(0);
        showMessage("Output copied to clipboard!", "Copied");
    }

    private void showMessage(String message, String title) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
    
    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        if (!ThemeManager.applyTheme(new AppPreferences().getTheme())) {
            log.warn("Theme setup failed; falling back to default look and feel");
        }

        // Create and show the application
        SwingUtilities.invokeLater(() -> {
            new EncodingDecodingApp().setVisible(true);
        });
    }
}