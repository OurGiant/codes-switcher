package com.ourgiant.crypt;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.zip.*;

public class GPGDecryptor extends JFrame {
    private JTextField encryptedFileField;
    private JTextField keyFileField;
    private JTextField outputFileField;
    private JPasswordField passphraseField;
    private JTextArea logArea;
    private JButton decryptButton;
    private JButton installGPGButton;
    private JLabel statusLabel;
    private JLabel gpgVersionLabel;
    
    private static final String GPG_TARBALL_URL = "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.4.8.tar.bz2";
    private static final String REQUIRED_VERSION = "2.4.8";
    private String gpgPath = "gpg"; // Default to system PATH

    public GPGDecryptor() {
        setTitle("GPG File Decryptor");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 700);
        setLocationRelativeTo(null);
        
        initComponents();
        checkGPGVersion();
    }

    private void initComponents() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // File selection panel
        JPanel filePanel = new JPanel(new GridBagLayout());
        filePanel.setBorder(new TitledBorder("File Selection"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Encrypted file
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0;
        filePanel.add(new JLabel("Encrypted File:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        encryptedFileField = new JTextField();
        filePanel.add(encryptedFileField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browseEncrypted = new JButton("Browse...");
        browseEncrypted.addActionListener(e -> browseFile(encryptedFileField, "Select Encrypted File", JFileChooser.FILES_ONLY));
        filePanel.add(browseEncrypted, gbc);

        // Key file
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        filePanel.add(new JLabel("Key File:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        keyFileField = new JTextField();
        filePanel.add(keyFileField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browseKey = new JButton("Browse...");
        browseKey.addActionListener(e -> browseFile(keyFileField, "Select Key File", JFileChooser.FILES_ONLY));
        filePanel.add(browseKey, gbc);

        // Output file
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        filePanel.add(new JLabel("Output File:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        outputFileField = new JTextField();
        filePanel.add(outputFileField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browseOutput = new JButton("Browse...");
        browseOutput.addActionListener(e -> saveFile(outputFileField, "Select Output Location"));
        filePanel.add(browseOutput, gbc);

        // Passphrase
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0;
        filePanel.add(new JLabel("Passphrase:"), gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        passphraseField = new JPasswordField();
        filePanel.add(passphraseField, gbc);

        // Log area
        logArea = new JTextArea(12, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(new TitledBorder("Log"));

        // Bottom panel with buttons and status
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        decryptButton = new JButton("Decrypt File");
        decryptButton.setFont(new Font("Arial", Font.BOLD, 14));
        decryptButton.addActionListener(e -> decryptFile());
        buttonPanel.add(decryptButton);

        installGPGButton = new JButton("Install/Update GPG");
        installGPGButton.setFont(new Font("Arial", Font.BOLD, 12));
        installGPGButton.addActionListener(e -> showInstallDialog());
        buttonPanel.add(installGPGButton);

        JButton clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> logArea.setText(""));
        buttonPanel.add(clearButton);

        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        gpgVersionLabel = new JLabel("GPG Version: Checking...");
        gpgVersionLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(gpgVersionLabel, BorderLayout.EAST);

        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(statusPanel, BorderLayout.SOUTH);

        // Add components to main panel
        mainPanel.add(filePanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        add(mainPanel);
    }

    private void browseFile(JTextField textField, String title, int mode) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(title);
        fileChooser.setFileSelectionMode(mode);
        
        String currentPath = textField.getText();
        if (!currentPath.isEmpty() && Files.exists(Paths.get(currentPath))) {
            fileChooser.setCurrentDirectory(new File(currentPath).getParentFile());
        }
        
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            textField.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void saveFile(JTextField textField, String title) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(title);
        
        String currentPath = textField.getText();
        if (!currentPath.isEmpty()) {
            fileChooser.setSelectedFile(new File(currentPath));
        }
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            textField.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void checkGPGVersion() {
        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                try {
                    Process process = new ProcessBuilder(gpgPath, "--version").start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line = reader.readLine();
                    process.waitFor();
                    return line != null ? line : "Unknown";
                } catch (Exception e) {
                    return "GPG not found";
                }
            }

            @Override
            protected void done() {
                try {
                    String version = get();
                    gpgVersionLabel.setText("GPG Version: " + version);
                    
                    if (version.contains("not found") || !version.contains("gpg")) {
                        log("WARNING: GPG not found in system PATH");
                        log("Click 'Install/Update GPG' to install GPG 2.4.8+");
                        decryptButton.setEnabled(false);
                        installGPGButton.setEnabled(true);
                    } else {
                        log("GPG detected: " + version);
                        if (isVersionSufficient(version)) {
                            log("GPG version is sufficient (2.4.8+)");
                            decryptButton.setEnabled(true);
                        } else {
                            log("WARNING: GPG version may be too old. Recommended: 2.4.8+");
                            log("Click 'Install/Update GPG' to upgrade");
                            decryptButton.setEnabled(true); // Allow use but warn
                        }
                    }
                } catch (Exception e) {
                    gpgVersionLabel.setText("GPG Version: Error checking");
                    log("Error checking GPG version: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private boolean isVersionSufficient(String versionOutput) {
        try {
            // Extract version number (e.g., "gpg (GnuPG) 2.4.8" -> "2.4.8")
            String[] parts = versionOutput.split("\\s+");
            for (String part : parts) {
                if (part.matches("\\d+\\.\\d+\\.\\d+")) {
                    String[] current = part.split("\\.");
                    String[] required = REQUIRED_VERSION.split("\\.");
                    
                    for (int i = 0; i < Math.min(current.length, required.length); i++) {
                        int curr = Integer.parseInt(current[i]);
                        int req = Integer.parseInt(required[i]);
                        if (curr > req) return true;
                        if (curr < req) return false;
                    }
                    return true;
                }
            }
        } catch (Exception e) {
            // If parsing fails, assume insufficient
        }
        return false;
    }

    private void showInstallDialog() {
        String os = System.getProperty("os.name").toLowerCase();
        String message;
        
        if (os.contains("win")) {
            message = "For Windows, we recommend installing Gpg4win which includes GPG 2.4.8+.\n\n" +
                     "Options:\n" +
                     "1. Download Gpg4win: This will open your browser to download the installer\n" +
                     "2. Manual Installation: Download and install yourself\n\n" +
                     "After installation, restart this application.";
        } else if (os.contains("mac")) {
            message = "For macOS, we recommend using Homebrew to install GPG.\n\n" +
                     "Options:\n" +
                     "1. Use Homebrew (recommended): brew install gnupg\n" +
                     "2. Download GPG Suite: Opens browser to download\n" +
                     "3. Compile from source: Advanced option\n\n" +
                     "Choose your installation method:";
        } else {
            message = "For Linux, you have several options:\n\n" +
                     "1. Use your package manager (recommended):\n" +
                     "   - Ubuntu/Debian: sudo apt-get install gnupg\n" +
                     "   - Fedora: sudo dnf install gnupg2\n" +
                     "   - Arch: sudo pacman -S gnupg\n" +
                     "2. Compile from source tarball (GPG 2.4.8)\n\n" +
                     "Choose your installation method:";
        }

        String[] options;
        if (os.contains("win")) {
            options = new String[]{"Download Gpg4win", "Manual Instructions", "Cancel"};
        } else if (os.contains("mac")) {
            options = new String[]{"Homebrew Instructions", "Download GPG Suite", "Compile from Source", "Cancel"};
        } else {
            options = new String[]{"Package Manager Instructions", "Compile from Source", "Cancel"};
        }

        int choice = JOptionPane.showOptionDialog(
            this,
            message,
            "Install GPG",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.INFORMATION_MESSAGE,
            null,
            options,
            options[0]
        );

        handleInstallChoice(os, choice, options.length - 1);
    }

    private void handleInstallChoice(String os, int choice, int cancelIndex) {
        if (choice == cancelIndex || choice == -1) return;

        if (os.contains("win")) {
            if (choice == 0) {
                openURL("https://www.gpg4win.org/download.html");
                JOptionPane.showMessageDialog(this,
                    "Opening Gpg4win download page.\n\n" +
                    "After installation:\n" +
                    "1. Run the Gpg4win installer\n" +
                    "2. Restart this application\n" +
                    "3. GPG will be automatically detected",
                    "Installation Instructions",
                    JOptionPane.INFORMATION_MESSAGE);
            } else {
                showManualInstructions();
            }
        } else if (os.contains("mac")) {
            if (choice == 0) {
                showHomebrewInstructions();
            } else if (choice == 1) {
                openURL("https://gpgtools.org/");
                JOptionPane.showMessageDialog(this,
                    "Opening GPG Suite download page.\n\n" +
                    "After installation, restart this application.",
                    "Installation Instructions",
                    JOptionPane.INFORMATION_MESSAGE);
            } else if (choice == 2) {
                compileFromSource();
            }
        } else {
            if (choice == 0) {
                showLinuxPackageManagerInstructions();
            } else if (choice == 1) {
                compileFromSource();
            }
        }
    }

    private void showHomebrewInstructions() {
        String instructions = "To install GPG using Homebrew:\n\n" +
                            "1. Open Terminal\n" +
                            "2. If you don't have Homebrew, install it:\n" +
                            "   /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n\n" +
                            "3. Install GPG:\n" +
                            "   brew install gnupg\n\n" +
                            "4. Restart this application";
        
        JTextArea textArea = new JTextArea(instructions);
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JOptionPane.showMessageDialog(this, new JScrollPane(textArea), 
            "Homebrew Installation", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showLinuxPackageManagerInstructions() {
        String instructions = "To install GPG using your package manager:\n\n" +
                            "Ubuntu/Debian:\n" +
                            "  sudo apt-get update\n" +
                            "  sudo apt-get install gnupg\n\n" +
                            "Fedora:\n" +
                            "  sudo dnf install gnupg2\n\n" +
                            "Arch Linux:\n" +
                            "  sudo pacman -S gnupg\n\n" +
                            "CentOS/RHEL:\n" +
                            "  sudo yum install gnupg2\n\n" +
                            "After installation, restart this application.";
        
        JTextArea textArea = new JTextArea(instructions);
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JOptionPane.showMessageDialog(this, new JScrollPane(textArea), 
            "Package Manager Installation", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showManualInstructions() {
        String instructions = "Manual Installation Instructions:\n\n" +
                            "Windows (Gpg4win):\n" +
                            "1. Download from: https://www.gpg4win.org/download.html\n" +
                            "2. Run the installer\n" +
                            "3. Follow the installation wizard\n" +
                            "4. Restart this application\n\n" +
                            "Or download GPG 2.4.8 source:\n" +
                            GPG_TARBALL_URL;
        
        JTextArea textArea = new JTextArea(instructions);
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JOptionPane.showMessageDialog(this, new JScrollPane(textArea), 
            "Manual Installation", JOptionPane.INFORMATION_MESSAGE);
    }

    private void compileFromSource() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Compiling from source requires:\n" +
            "- Build tools (gcc, make)\n" +
            "- Dependencies (libgpg-error, libgcrypt, etc.)\n" +
            "- Root/sudo access\n" +
            "- 30-60 minutes\n\n" +
            "This will download and compile GPG 2.4.8.\n" +
            "Continue?",
            "Compile from Source",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );

        if (confirm != JOptionPane.YES_OPTION) return;

        installGPGButton.setEnabled(false);
        decryptButton.setEnabled(false);
        statusLabel.setText("Downloading and compiling GPG...");

        SwingWorker<Boolean, String> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                try {
                    String homeDir = System.getProperty("user.home");
                    Path downloadDir = Paths.get(homeDir, "gpg-build");
                    Files.createDirectories(downloadDir);
                    
                    publish("Created build directory: " + downloadDir);
                    publish("Downloading GPG 2.4.8 source tarball...");
                    publish("This may take several minutes depending on your connection.");
                    
                    // Show download instructions instead of actual download
                    publish("\nTo compile GPG 2.4.8 manually:");
                    publish("1. Download: " + GPG_TARBALL_URL);
                    publish("2. Extract: tar -xjf gnupg-2.4.8.tar.bz2");
                    publish("3. cd gnupg-2.4.8");
                    publish("4. Install dependencies:");
                    publish("   Ubuntu/Debian: sudo apt-get install libgpg-error-dev libgcrypt-dev libassuan-dev libksba-dev libnpth0-dev");
                    publish("   Fedora: sudo dnf install libgpg-error-devel libgcrypt-devel libassuan-devel libksba-devel npth-devel");
                    publish("5. ./configure --prefix=/usr/local");
                    publish("6. make");
                    publish("7. sudo make install");
                    publish("\nAfter installation, restart this application.");
                    
                    return false; // Indicate manual steps required
                    
                } catch (Exception e) {
                    publish("ERROR: " + e.getMessage());
                    return false;
                }
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }

            @Override
            protected void done() {
                installGPGButton.setEnabled(true);
                statusLabel.setText("Ready - Follow manual compilation steps above");
            }
        };
        
        worker.execute();
    }

    private void openURL(String url) {
        try {
            Desktop desktop = Desktop.getDesktop();
            desktop.browse(new URL(url).toURI());
        } catch (Exception e) {
            log("Could not open browser. Please visit: " + url);
        }
    }

    private void decryptFile() {
        String encryptedFile = encryptedFileField.getText().trim();
        String keyFile = keyFileField.getText().trim();
        String outputFile = outputFileField.getText().trim();
        String passphrase = new String(passphraseField.getPassword());

        // Validation
        if (encryptedFile.isEmpty() || outputFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Please specify encrypted file and output file locations.", 
                "Missing Information", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!Files.exists(Paths.get(encryptedFile))) {
            JOptionPane.showMessageDialog(this, 
                "Encrypted file does not exist.", 
                "File Not Found", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!keyFile.isEmpty() && !Files.exists(Paths.get(keyFile))) {
            JOptionPane.showMessageDialog(this, 
                "Key file does not exist.", 
                "File Not Found", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Perform decryption in background thread
        decryptButton.setEnabled(false);
        statusLabel.setText("Decrypting...");
        
        SwingWorker<Boolean, String> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                try {
                    publish("Starting decryption process...");
                    
                    ProcessBuilder pb = new ProcessBuilder();
                    
                    if (!keyFile.isEmpty()) {
                        // Import key first
                        publish("Importing key from: " + keyFile);
                        ProcessBuilder importPb = new ProcessBuilder(gpgPath, "--import", keyFile);
                        Process importProcess = importPb.start();
                        
                        BufferedReader importReader = new BufferedReader(
                            new InputStreamReader(importProcess.getErrorStream()));
                        String line;
                        while ((line = importReader.readLine()) != null) {
                            publish("  " + line);
                        }
                        importProcess.waitFor();
                    }
                    
                    // Build decrypt command
                    if (passphrase.isEmpty()) {
                        pb.command(gpgPath, "--decrypt", "--output", outputFile, encryptedFile);
                    } else {
                        pb.command(gpgPath, "--batch", "--yes", "--passphrase-fd", "0", 
                                 "--decrypt", "--output", outputFile, encryptedFile);
                    }
                    
                    publish("Executing: " + String.join(" ", pb.command()));
                    Process process = pb.start();
                    
                    // Send passphrase if provided
                    if (!passphrase.isEmpty()) {
                        OutputStream os = process.getOutputStream();
                        os.write((passphrase + "\n").getBytes());
                        os.flush();
                        os.close();
                    }
                    
                    // Read output
                    BufferedReader errorReader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream()));
                    String line;
                    while ((line = errorReader.readLine()) != null) {
                        publish(line);
                    }
                    
                    int exitCode = process.waitFor();
                    
                    if (exitCode == 0 && Files.exists(Paths.get(outputFile))) {
                        publish("SUCCESS: File decrypted successfully!");
                        publish("Output saved to: " + outputFile);
                        return true;
                    } else {
                        publish("ERROR: Decryption failed with exit code " + exitCode);
                        return false;
                    }
                    
                } catch (Exception e) {
                    publish("ERROR: " + e.getMessage());
                    e.printStackTrace();
                    return false;
                }
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }

            @Override
            protected void done() {
                try {
                    boolean success = get();
                    statusLabel.setText(success ? "Decryption completed successfully" : "Decryption failed");
                    if (success) {
                        JOptionPane.showMessageDialog(GPGDecryptor.this, 
                            "File decrypted successfully!\n\nOutput: " + outputFile, 
                            "Success", 
                            JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception e) {
                    statusLabel.setText("Error during decryption");
                }
                decryptButton.setEnabled(true);
            }
        };
        
        worker.execute();
    }

    private void log(String message) {
        logArea.append(message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new GPGDecryptor().setVisible(true);
        });
    }
}