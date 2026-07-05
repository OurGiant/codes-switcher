package com.ourgiant.crypt;

import javax.swing.*;
import java.awt.*;

public class AppLauncher extends JFrame {

    public AppLauncher() {
        setTitle("Codes Switcher");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(360, 180);
        setLocationRelativeTo(null);
        setLayout(new GridLayout(0, 1, 10, 10));

        JLabel label = new JLabel("Choose a tool", SwingConstants.CENTER);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 16f));

        JButton gpgButton = new JButton("GPG Decryptor");
        gpgButton.addActionListener(e -> {
            new GPGDecryptor().setVisible(true);
            dispose();
        });

        JButton encodingButton = new JButton("Encoder / Decoder");
        encodingButton.addActionListener(e -> {
            new EncodingDecodingApp().setVisible(true);
            dispose();
        });

        ((JPanel) getContentPane()).setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        add(label);
        add(gpgButton);
        add(encodingButton);
    }

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Use default look and feel if system L&F is not available
        }

        SwingUtilities.invokeLater(() -> new AppLauncher().setVisible(true));
    }
}
