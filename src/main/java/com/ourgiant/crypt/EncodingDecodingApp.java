package com.ourgiant.crypt;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class EncodingDecodingApp extends JFrame {
    private JComboBox<String> methodComboBox;
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JButton encodeButton;
    private JButton decodeButton;
    private JButton clearButton;
    private JButton copyButton;
    private JButton swapButton;
    
    // Encoding methods
    private static final String BASE64 = "Base64";
    private static final String URL = "URL";
    private static final String HTML = "HTML";
    private static final String HEX = "Hexadecimal";
    private static final String BINARY = "Binary";
    private static final String ROT13 = "ROT13";
    private static final String SHA256 = "SHA-256 (Hash)";
    private static final String SHA512 = "SHA-512 (Hash)";
    private static final String MD5 = "MD5 (Hash)";
    private static final String JSON = "JSON Escape";
    private static final String JWT = "JWT (Decode Only)";
    
    public EncodingDecodingApp() {
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("Universal Encoder/Decoder v1.0");
        setSize(800, 600);
        setLocationRelativeTo(null);
        
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
            String encoded = encode(input, (String) methodComboBox.getSelectedItem());
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
            String decoded = decode(input, (String) methodComboBox.getSelectedItem());
            outputTextArea.setText(decoded);
            outputTextArea.setCaretPosition(0);
        } catch (Exception e) {
            showMessage("Decoding failed: " + e.getMessage(), "Error");
        }
    }
    
    private String encode(String input, String method) throws Exception {
        switch (method) {
            case BASE64:
                return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
            
            case URL:
                return URLEncoder.encode(input, StandardCharsets.UTF_8.toString());
            
            case HTML:
                return htmlEncode(input);
            
            case HEX:
                return bytesToHex(input.getBytes(StandardCharsets.UTF_8));
            
            case BINARY:
                return stringToBinary(input);
            
            case ROT13:
                return rot13(input);
            
            case JSON:
                return jsonEscape(input);
            
            case JWT:
                throw new UnsupportedOperationException("JWT encoding not supported - use a proper JWT library for token creation");
            
            case SHA256:
                return hashString(input, "SHA-256");
            
            case SHA512:
                return hashString(input, "SHA-512");
            
            case MD5:
                return hashString(input, "MD5");
            
            default:
                throw new IllegalArgumentException("Unknown encoding method: " + method);
        }
    }
    
    private String decode(String input, String method) throws Exception {
        switch (method) {
            case BASE64:
                return new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8);
            
            case URL:
                return URLDecoder.decode(input, StandardCharsets.UTF_8.toString());
            
            case HTML:
                return htmlDecode(input);
            
            case HEX:
                return new String(hexToBytes(input), StandardCharsets.UTF_8);
            
            case BINARY:
                return binaryToString(input);
            
            case ROT13:
                return rot13(input); // ROT13 is its own inverse
            
            case JSON:
                return jsonUnescape(input);
            
            case JWT:
                return decodeJWT(input);
            
            case SHA256:
            case SHA512:
            case MD5:
                throw new UnsupportedOperationException("Hash functions cannot be decoded (one-way only)");
            
            default:
                throw new IllegalArgumentException("Unknown decoding method: " + method);
        }
    }
    
    private String htmlEncode(String input) {
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;")
                   .replace("/", "&#x2F;");
    }
    
    private String htmlDecode(String input) {
        return input.replace("&amp;", "&")
                   .replace("&lt;", "<")
                   .replace("&gt;", ">")
                   .replace("&quot;", "\"")
                   .replace("&#x27;", "'")
                   .replace("&#x2F;", "/");
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    private byte[] hexToBytes(String hex) throws Exception {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }
    
    // New encoding methods
    private String stringToBinary(String input) {
        StringBuilder binary = new StringBuilder();
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            binary.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return binary.toString();
    }
    
    private String binaryToString(String binary) throws Exception {
        if (binary.length() % 8 != 0) {
            throw new IllegalArgumentException("Binary string length must be divisible by 8");
        }
        
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteString = binary.substring(i, i + 8);
            int byteValue = Integer.parseInt(byteString, 2);
            result.append((char) byteValue);
        }
        return result.toString();
    }
    
    private String rot13(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String jsonEscape(String input) {
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\b", "\\b")
                   .replace("\f", "\\f")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t")
                   .replace("/", "\\/");
    }
    
    private String jsonUnescape(String input) {
        return input.replace("\\\\", "\\")
                   .replace("\\\"", "\"")
                   .replace("\\b", "\b")
                   .replace("\\f", "\f")
                   .replace("\\n", "\n")
                   .replace("\\r", "\r")
                   .replace("\\t", "\t")
                   .replace("\\/", "/");
    }
    
    private String hashString(String input, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }
    
    private String decodeJWT(String jwt) throws Exception {
        // Remove any whitespace
        jwt = jwt.trim();
        
        // JWT format: header.payload.signature
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format. Expected 3 parts separated by dots, got " + parts.length);
        }
        
        StringBuilder result = new StringBuilder();
        
        try {
            // Decode header
            String header = decodeJWTPart(parts[0]);
            result.append("=== JWT HEADER ===\n");
            result.append(formatJSON(header));
            result.append("\n\n");
            
            // Decode payload
            String payload = decodeJWTPart(parts[1]);
            result.append("=== JWT PAYLOAD ===\n");
            result.append(formatJSON(payload));
            result.append("\n\n");
            
            // Show signature info (can't decode without key)
            result.append("=== JWT SIGNATURE ===\n");
            result.append("Raw: ").append(parts[2]).append("\n");
            result.append("Note: Signature verification requires the secret key\n");
            result.append("Length: ").append(parts[2].length()).append(" characters");
            
        } catch (Exception e) {
            throw new Exception("JWT decoding failed: " + e.getMessage());
        }
        
        return result.toString();
    }
    
    private String decodeJWTPart(String part) throws Exception {
        // JWT uses Base64 URL encoding (no padding)
        // Convert to standard Base64 by adding padding if needed
        String padded = part;
        while (padded.length() % 4 != 0) {
            padded += "=";
        }
        
        // Replace URL-safe characters
        padded = padded.replace('-', '+').replace('_', '/');
        
        // Decode
        byte[] decoded = Base64.getDecoder().decode(padded);
        return new String(decoded, StandardCharsets.UTF_8);
    }
    
    private String formatJSON(String json) {
        // Simple JSON formatting - add indentation
        StringBuilder formatted = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        char prev = 0;
        
        for (char c : json.toCharArray()) {
            if (c == '"' && prev != '\\') {
                inString = !inString;
            }
            
            if (!inString) {
                switch (c) {
                    case '{':
                    case '[':
                        formatted.append(c).append('\n');
                        indent++;
                        addIndent(formatted, indent);
                        break;
                    case '}':
                    case ']':
                        formatted.append('\n');
                        indent--;
                        addIndent(formatted, indent);
                        formatted.append(c);
                        break;
                    case ',':
                        formatted.append(c).append('\n');
                        addIndent(formatted, indent);
                        break;
                    case ':':
                        formatted.append(c).append(' ');
                        break;
                    default:
                        formatted.append(c);
                }
            } else {
                formatted.append(c);
            }
            prev = c;
        }
        
        return formatted.toString();
    }
    
    private void addIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
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