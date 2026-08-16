package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.cert.ChainValidator;
import com.ourgiant.crypt.crypto.cert.X509Inspector;
import com.ourgiant.crypt.crypto.jwt.JwksKeys;
import com.ourgiant.crypt.crypto.jwt.JwtParser;
import com.ourgiant.crypt.crypto.jwt.JwtVerification;
import com.ourgiant.crypt.crypto.jwt.PemPublicKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * JWT signature verification and X.509 certificate inspection - two tabs in one window rather
 * than cramming multi-field forms into EncodingDecodingApp's simple single-input/single-output
 * layout, which isn't built for that shape. All the actual crypto logic lives in
 * crypto/jwt and crypto/cert (pure, unit-tested); this class is Swing wiring only.
 */
public class CryptoInspectorApp extends JFrame {
    private static final Logger log = LoggerFactory.getLogger(CryptoInspectorApp.class);
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ISO_INSTANT;

    private JTextArea jwtInput;
    private JRadioButton hmacOption;
    private JRadioButton publicKeyOption;
    private JRadioButton jwksOption;
    private CardLayout keyMaterialLayout;
    private JPanel keyMaterialPanel;
    private JTextField hmacSecretField;
    private JTextArea publicKeyArea;
    private JTextField jwksUrlField;
    private JButton verifyButton;
    private JTextArea jwtResultArea;

    private JTextArea certInput;
    private JButton inspectButton;
    private JTextArea certResultArea;

    public CryptoInspectorApp() {
        setTitle("JWT / X.509 Inspector");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(820, 700);
        setLocationRelativeTo(null);
        setJMenuBar(AppLauncher.createMenuBar(this));

        Image icon = AppLauncher.loadAppIcon();
        if (icon != null) {
            setIconImage(icon);
        }

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("JWT Verifier", buildJwtTab());
        tabs.addTab("X.509 Inspector", buildCertTab());
        add(tabs);
    }

    // ============================== JWT tab ==============================

    private JPanel buildJwtTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new BorderLayout(4, 4));
        topPanel.add(new JLabel("JWT Token:"), BorderLayout.NORTH);
        jwtInput = new JTextArea(4, 60);
        jwtInput.setLineWrap(true);
        jwtInput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        topPanel.add(new JScrollPane(jwtInput), BorderLayout.CENTER);
        topPanel.add(buildKeyMaterialPanel(), BorderLayout.SOUTH);
        panel.add(topPanel, BorderLayout.NORTH);

        jwtResultArea = new JTextArea();
        jwtResultArea.setEditable(false);
        jwtResultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        jwtResultArea.setBackground(new Color(245, 245, 245));
        panel.add(new JScrollPane(jwtResultArea), BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildKeyMaterialPanel() {
        JPanel container = new JPanel(new BorderLayout(4, 4));
        container.setBorder(BorderFactory.createTitledBorder("Verify Against"));

        JPanel radioRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hmacOption = new JRadioButton("HMAC Secret", true);
        publicKeyOption = new JRadioButton("Public Key (PEM)");
        jwksOption = new JRadioButton("JWKS URL");
        ButtonGroup group = new ButtonGroup();
        group.add(hmacOption);
        group.add(publicKeyOption);
        group.add(jwksOption);
        radioRow.add(hmacOption);
        radioRow.add(publicKeyOption);
        radioRow.add(jwksOption);
        container.add(radioRow, BorderLayout.NORTH);

        keyMaterialLayout = new CardLayout();
        keyMaterialPanel = new JPanel(keyMaterialLayout);

        hmacSecretField = new JTextField();
        keyMaterialPanel.add(labeledField("Shared secret (UTF-8 text):", hmacSecretField), "hmac");

        publicKeyArea = new JTextArea(4, 60);
        publicKeyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel pemPanel = new JPanel(new BorderLayout());
        pemPanel.add(new JLabel("Public key (PEM, \"-----BEGIN PUBLIC KEY-----\"):"), BorderLayout.NORTH);
        pemPanel.add(new JScrollPane(publicKeyArea), BorderLayout.CENTER);
        keyMaterialPanel.add(pemPanel, "key");

        jwksUrlField = new JTextField();
        keyMaterialPanel.add(labeledField("JWKS URL (e.g. https://issuer/.well-known/jwks.json):", jwksUrlField), "jwks");

        container.add(keyMaterialPanel, BorderLayout.CENTER);

        hmacOption.addActionListener(e -> keyMaterialLayout.show(keyMaterialPanel, "hmac"));
        publicKeyOption.addActionListener(e -> keyMaterialLayout.show(keyMaterialPanel, "key"));
        jwksOption.addActionListener(e -> keyMaterialLayout.show(keyMaterialPanel, "jwks"));

        verifyButton = new JButton("Verify");
        verifyButton.addActionListener(e -> performJwtVerification());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(verifyButton);
        container.add(buttonRow, BorderLayout.SOUTH);

        return container;
    }

    private JPanel labeledField(String label, JTextField field) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JLabel(label), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        return panel;
    }

    private void performJwtVerification() {
        String jwt = jwtInput.getText().trim();
        if (jwt.isEmpty()) {
            showMessage("Paste a JWT token first.", "Input Required");
            return;
        }

        verifyButton.setEnabled(false);
        jwtResultArea.setText("Verifying...");

        new SwingWorker<JwtVerification.Outcome, Void>() {
            @Override
            protected JwtVerification.Outcome doInBackground() {
                if (hmacOption.isSelected()) {
                    byte[] secret = hmacSecretField.getText().getBytes(StandardCharsets.UTF_8);
                    return JwtVerification.verifyHmac(jwt, secret);
                }
                if (publicKeyOption.isSelected()) {
                    try {
                        var key = PemPublicKeys.parse(publicKeyArea.getText());
                        return JwtVerification.verifyWithPublicKey(jwt, key);
                    } catch (PemPublicKeys.InvalidPemException e) {
                        return errorOutcome(e.getMessage());
                    }
                }
                try {
                    return JwtVerification.verifyWithJwks(jwt, jwksUrlField.getText().trim());
                } catch (JwksKeys.JwksException e) {
                    return errorOutcome(e.getMessage());
                }
            }

            @Override
            protected void done() {
                verifyButton.setEnabled(true);
                try {
                    jwtResultArea.setText(formatOutcome(get()));
                } catch (Exception e) {
                    log.error("JWT verification failed unexpectedly", e);
                    jwtResultArea.setText("Unexpected error: " + e.getMessage());
                }
                jwtResultArea.setCaretPosition(0);
            }
        }.execute();
    }

    private static JwtVerification.Outcome errorOutcome(String message) {
        return new JwtVerification.Outcome(null, false, null, message, JwtVerification.TimeStatus.NO_TIME_CLAIMS, null);
    }

    private String formatOutcome(JwtVerification.Outcome outcome) {
        StringBuilder sb = new StringBuilder();
        if (outcome.token() == null) {
            sb.append("=== ERROR ===\n").append(outcome.error());
            return sb.toString();
        }

        JwtParser.ParsedJwt token = outcome.token();
        sb.append("=== HEADER ===\n").append(TextCodec.formatJSON(token.headerJson())).append("\n\n");
        sb.append("=== PAYLOAD ===\n").append(TextCodec.formatJSON(token.payloadJson())).append("\n\n");

        sb.append("=== SIGNATURE ===\n");
        if (!outcome.algorithmMatchesKeyType()) {
            sb.append("NOT VERIFIED - algorithm mismatch\n").append(outcome.error()).append("\n");
        } else if (outcome.signatureValid() == null) {
            sb.append("NOT VERIFIED\n").append(outcome.error() != null ? outcome.error() : "(unknown reason)").append("\n");
        } else if (outcome.signatureValid()) {
            sb.append("VALID - signature matches\n");
        } else {
            sb.append("INVALID - signature does NOT match").append(outcome.error() != null ? " (" + outcome.error() + ")" : "").append("\n");
        }

        sb.append("\n=== TIME VALIDITY ===\n");
        sb.append(outcome.timeStatus()).append(outcome.timeDetail() != null ? " - " + outcome.timeDetail() : "");

        return sb.toString();
    }

    // ============================== X.509 tab ==============================

    private JPanel buildCertTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new BorderLayout(4, 4));
        topPanel.add(new JLabel("Certificate (PEM, or leaf+intermediate+root PEMs concatenated for chain validation):"),
            BorderLayout.NORTH);
        certInput = new JTextArea(8, 60);
        certInput.setLineWrap(true);
        certInput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        topPanel.add(new JScrollPane(certInput), BorderLayout.CENTER);

        inspectButton = new JButton("Inspect");
        inspectButton.addActionListener(e -> performCertInspection());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(inspectButton);
        topPanel.add(buttonRow, BorderLayout.SOUTH);

        panel.add(topPanel, BorderLayout.NORTH);

        certResultArea = new JTextArea();
        certResultArea.setEditable(false);
        certResultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        certResultArea.setBackground(new Color(245, 245, 245));
        panel.add(new JScrollPane(certResultArea), BorderLayout.CENTER);

        return panel;
    }

    private void performCertInspection() {
        String input = certInput.getText().trim();
        if (input.isEmpty()) {
            showMessage("Paste a certificate first.", "Input Required");
            return;
        }

        try {
            List<X509Certificate> certs = X509Inspector.parseChain(input);
            certResultArea.setText(formatCertReport(certs));
            certResultArea.setCaretPosition(0);
        } catch (X509Inspector.CertParseException e) {
            certResultArea.setText("=== ERROR ===\n" + e.getMessage());
        }
    }

    private String formatCertReport(List<X509Certificate> certs) {
        StringBuilder sb = new StringBuilder();
        X509Inspector.Inspection leaf = X509Inspector.inspect(certs.get(0));

        sb.append("=== CERTIFICATE").append(certs.size() > 1 ? " (leaf)" : "").append(" ===\n");
        appendInspection(sb, leaf);

        if (certs.size() > 1) {
            sb.append("\n=== CHAIN VALIDATION (").append(certs.size()).append(" certificates) ===\n");
            ChainValidator.ChainResult chainResult = ChainValidator.validate(certs);
            sb.append("Overall: ").append(chainResult.allValid() ? "VALID chain" : "INVALID chain").append("\n\n");
            int i = 1;
            for (ChainValidator.LinkResult link : chainResult.links()) {
                sb.append(i++).append(". ").append(link.subject()).append("\n");
                sb.append("   verified against: ").append(link.verifiedAgainst()).append("\n");
                sb.append("   ").append(link.signatureValid() ? "VALID" : "INVALID").append(" - ").append(link.detail()).append("\n");
            }
        }

        return sb.toString();
    }

    private void appendInspection(StringBuilder sb, X509Inspector.Inspection inspection) {
        sb.append("Subject: ").append(inspection.subject()).append("\n");
        sb.append("Issuer: ").append(inspection.issuer()).append("\n");
        sb.append("Valid from: ").append(TIME_FORMAT.format(inspection.notBefore())).append("\n");
        sb.append("Valid until: ").append(TIME_FORMAT.format(inspection.notAfter())).append("\n");
        sb.append("Key: ").append(inspection.keyAlgorithm());
        if (inspection.keySizeBits() > 0) {
            sb.append(" (").append(inspection.keySizeBits()).append(" bits)");
        }
        sb.append("\n");
        sb.append("SHA-256 Fingerprint: ").append(inspection.sha256Fingerprint()).append("\n");

        sb.append("Subject Alternative Names: ");
        sb.append(inspection.subjectAlternativeNames().isEmpty() ? "(none)"
            : String.join(", ", inspection.subjectAlternativeNames()));
        sb.append("\n");

        sb.append("Key Usage: ");
        sb.append(inspection.keyUsages().isEmpty() ? "(not specified)" : String.join(", ", inspection.keyUsages()));
        sb.append("\n\n");

        sb.append("--- Flags ---\n");
        sb.append("Expired: ").append(inspection.expired() ? "YES" : "no").append("\n");
        sb.append("Not yet valid: ").append(inspection.notYetValid() ? "YES" : "no").append("\n");
        sb.append("Self-signed: ").append(inspection.selfSigned()
            ? "YES" + (inspection.selfSignatureValid() ? " (self-signature verifies)" : " (WARNING: self-signature does NOT verify)")
            : "no").append("\n");
        sb.append("Weak key: ").append(inspection.weakKey() ? "YES - " + inspection.weakKeyDetail() : "no").append("\n");
    }

    private void showMessage(String message, String title) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
}
