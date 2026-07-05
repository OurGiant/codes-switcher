package com.ourgiant.crypt;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;

import static com.ourgiant.crypt.TextCodec.BASE64;
import static com.ourgiant.crypt.TextCodec.BINARY;
import static com.ourgiant.crypt.TextCodec.HEX;
import static com.ourgiant.crypt.TextCodec.HTML;
import static com.ourgiant.crypt.TextCodec.JSON;
import static com.ourgiant.crypt.TextCodec.JWT;
import static com.ourgiant.crypt.TextCodec.MD5;
import static com.ourgiant.crypt.TextCodec.ROT13;
import static com.ourgiant.crypt.TextCodec.SHA256;
import static com.ourgiant.crypt.TextCodec.SHA512;
import static com.ourgiant.crypt.TextCodec.URL;

public class EncodingDecodingApp extends JFrame {
    private JComboBox<String> methodComboBox;
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JButton encodeButton;
    private JButton decodeButton;
    private JButton clearButton;
    private JButton copyButton;
    private JButton swapButton;

    public EncodingDecodingApp() {
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("Universal Encoder/Decoder v1.0");
        setSize(800, 600);
        setLocationRelativeTo(null);
        setJMenuBar(AppLauncher.createFileMenu(this));

        // Set application icon (using a built-in icon)
        try {
            setIconImage(createAppIcon());
        } catch (Exception e) {
            // Ignore if icon creation fails
        }
    }
    
    private Image createAppIcon() {
        // Create a simple 16x16 icon
        java.awt.image.BufferedImage icon = new java.awt.image.BufferedImage(16, 16, java.awt.image.BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = icon.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2d.setColor(new Color(70, 130, 180));
        g2d.fillRect(0, 0, 16, 16);
        g2d.setColor(Color.WHITE);
        g2d.setFont(new Font("Arial", Font.BOLD, 10));
        g2d.drawString("E", 5, 12);
        g2d.dispose();
        return icon;
    }
    
    private void initializeComponents() {
        // Method selection
        methodComboBox = new JComboBox<>(new String[]{
            BASE64, URL, HTML, HEX, BINARY, ROT13, 
            JSON, JWT, SHA256, SHA512, MD5
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
        
        add(topPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private void setupEventHandlers() {
        encodeButton.addActionListener(e -> performEncoding());
        decodeButton.addActionListener(e -> performDecoding());
        clearButton.addActionListener(e -> clearAll());
        copyButton.addActionListener(e -> copyOutput());
        swapButton.addActionListener(e -> swapInputOutput());
        
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
    
    private void showMessage(String message, String title) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
    
    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        // Set system look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Use default look and feel if system L&F is not available
        }
        
        // Create and show the application
        SwingUtilities.invokeLater(() -> {
            new EncodingDecodingApp().setVisible(true);
        });
    }
}