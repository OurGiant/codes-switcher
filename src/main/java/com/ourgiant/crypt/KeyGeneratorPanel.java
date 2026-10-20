package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.cert.CertificateGenerator;
import com.ourgiant.crypt.crypto.cert.CertificateGenerator.CertRequest;
import com.ourgiant.crypt.crypto.cert.CertificateGenerator.KeyType;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/** JWT / X.509 Inspector tab that generates a key pair and, optionally, a self-signed certificate. */
public class KeyGeneratorPanel extends JPanel {

    private final JComboBox<KeyType> keyTypeBox = new JComboBox<>(KeyType.values());
    private final JCheckBox makeCert = new JCheckBox("Also create a self-signed certificate", true);
    private final JTextField cnField = new JTextField("localhost", 24);
    private final JTextField orgField = new JTextField(18);
    private final JTextField sansField = new JTextField(36);
    private final JSpinner daysSpinner = new JSpinner(new SpinnerNumberModel(365, 1, 36500, 1));
    private final JCheckBox caBox = new JCheckBox("Certificate authority (CA)");
    private final JTextArea privateArea = mono();
    private final JTextArea publicArea = mono();
    private final JTextArea certArea = mono();
    private final JTabbedPane outputs = new JTabbedPane();
    private final JButton generateButton = new JButton("Generate");
    private final JButton saveP12Button = new JButton("Save as PKCS#12…");
    private final JButton inspectButton = new JButton("Open in X.509 Inspector");

    private KeyPair keys;
    private X509Certificate cert;

    /** @param openInInspector receives the certificate PEM */
    public KeyGeneratorPanel(Consumer<String> openInInspector) {
        super(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        sansField.setToolTipText("Comma-separated host names and IPs, e.g. example.com, *.example.com, 10.0.0.5, email:me@example.com. "
                + "Empty: the CN is used.");
        caBox.setToolTipText("Mark as a CA that can sign other certificates (keyCertSign) instead of a TLS server/client certificate");

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new TitledBorder("Settings"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        int y = 0;
        add(form, c, y++, "Key type:", keyTypeBox);
        c.gridx = 1;
        c.gridy = y++;
        form.add(makeCert, c);
        add(form, c, y++, "Common name (CN):", cnField);
        add(form, c, y++, "Organization (O):", orgField);
        add(form, c, y++, "Subject alt names:", sansField);
        add(form, c, y++, "Valid for (days):", daysSpinner);
        c.gridx = 1;
        c.gridy = y;
        form.add(caBox, c);

        outputs.addTab("Private Key", new JScrollPane(privateArea));
        outputs.addTab("Public Key", new JScrollPane(publicArea));
        outputs.addTab("Certificate", new JScrollPane(certArea));

        JButton copy = new JButton("Copy Shown");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(generateButton);
        buttons.add(copy);
        buttons.add(saveP12Button);
        buttons.add(inspectButton);
        saveP12Button.setEnabled(false);
        inspectButton.setEnabled(false);

        JLabel warning = new JLabel("Keys are generated on this computer and never leave it. "
                + "The private key is shown unencrypted — store it safely.");
        warning.setFont(warning.getFont().deriveFont(Font.ITALIC));

        JPanel south = new JPanel(new BorderLayout());
        south.add(warning, BorderLayout.NORTH);
        south.add(buttons, BorderLayout.SOUTH);

        JPanel formHolder = new JPanel(new BorderLayout());
        formHolder.add(form, BorderLayout.WEST);
        add(formHolder, BorderLayout.NORTH);
        add(outputs, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        makeCert.addActionListener(e -> updateEnabled());
        generateButton.addActionListener(e -> generate());
        copy.addActionListener(e -> {
            JTextArea shown = (JTextArea) ((JScrollPane) outputs.getSelectedComponent()).getViewport().getView();
            shown.selectAll();
            shown.copy();
            shown.select(0, 0);
        });
        saveP12Button.addActionListener(e -> savePkcs12());
        inspectButton.addActionListener(e -> openInInspector.accept(certArea.getText()));
        updateEnabled();
    }

    private void updateEnabled() {
        boolean on = makeCert.isSelected();
        for (JComponent comp : new JComponent[]{cnField, orgField, sansField, daysSpinner, caBox}) {
            comp.setEnabled(on);
        }
    }

    private void generate() {
        KeyType type = (KeyType) keyTypeBox.getSelectedItem();
        boolean withCert = makeCert.isSelected();
        CertRequest req = new CertRequest(cnField.getText(), orgField.getText(),
                Arrays.stream(sansField.getText().split(",")).map(String::strip).filter(s -> !s.isEmpty()).toList(),
                (Integer) daysSpinner.getValue(), caBox.isSelected());

        generateButton.setEnabled(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        new SwingWorker<Object[], Void>() {
            @Override
            protected Object[] doInBackground() throws Exception {
                KeyPair kp = CertificateGenerator.generateKeyPair(type);
                X509Certificate c = withCert ? CertificateGenerator.selfSigned(kp, req) : null;
                return new Object[]{kp, c};
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                setCursor(null);
                try {
                    Object[] r = get();
                    keys = (KeyPair) r[0];
                    cert = (X509Certificate) r[1];
                    privateArea.setText(CertificateGenerator.privateKeyPem(keys.getPrivate()));
                    publicArea.setText(CertificateGenerator.publicKeyPem(keys.getPublic()));
                    certArea.setText(cert != null ? CertificateGenerator.certificatePem(cert) : "");
                    for (JTextArea a : List.of(privateArea, publicArea, certArea)) {
                        a.setCaretPosition(0);
                    }
                    outputs.setEnabledAt(2, cert != null);
                    outputs.setSelectedIndex(cert != null ? 2 : 0);
                    saveP12Button.setEnabled(cert != null);
                    inspectButton.setEnabled(cert != null);
                } catch (ExecutionException ex) {
                    JOptionPane.showMessageDialog(KeyGeneratorPanel.this, ex.getCause().getMessage(),
                            "Key Generator", JOptionPane.ERROR_MESSAGE);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    private void savePkcs12() {
        JPasswordField pw = new JPasswordField(20);
        JPasswordField again = new JPasswordField(20);
        int ok = JOptionPane.showConfirmDialog(this, new Object[]{"Password to protect the file:", pw, "Repeat:", again},
                "PKCS#12 Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        char[] p1 = pw.getPassword();
        char[] p2 = again.getPassword();
        try {
            if (p1.length == 0 || !Arrays.equals(p1, p2)) {
                JOptionPane.showMessageDialog(this, p1.length == 0 ? "A password is required." : "The passwords don't match.",
                        "PKCS#12 Password", JOptionPane.WARNING_MESSAGE);
                return;
            }
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new java.io.File(cnField.getText().strip().replaceAll("[^A-Za-z0-9._-]", "_") + ".p12"));
            if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            Files.write(chooser.getSelectedFile().toPath(), CertificateGenerator.pkcs12(keys, cert, "1", p1));
            JOptionPane.showMessageDialog(this, "Saved " + chooser.getSelectedFile().getName(), "Key Generator",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Couldn't save: " + ex.getMessage(), "Key Generator", JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(p1, '\0');
            Arrays.fill(p2, '\0');
        }
    }

    private static void add(JPanel form, GridBagConstraints c, int y, String label, JComponent field) {
        c.gridx = 0;
        c.gridy = y;
        form.add(new JLabel(label), c);
        c.gridx = 1;
        form.add(field, c);
    }

    private static JTextArea mono() {
        JTextArea a = new JTextArea(10, 64);
        a.setEditable(false);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return a;
    }
}
