package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.jwt.JwtSigner;
import com.ourgiant.crypt.crypto.jwt.PemPrivateKeys;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.function.BiConsumer;

/** JWT/X.509 Inspector tab that creates and signs a JWT from header/payload JSON. */
public class JwtBuilderPanel extends JPanel {

    private static final String HEADER_TEMPLATE = "{\n  \"typ\": \"JWT\"\n}";
    private static final String PAYLOAD_TEMPLATE = "{\n  \"sub\": \"1234567890\",\n  \"name\": \"Jane Doe\"\n}";

    private final JComboBox<String> algorithmBox = new JComboBox<>(JwtSigner.ALGORITHMS.toArray(String[]::new));
    private final JTextArea headerArea = mono(4);
    private final JTextArea payloadArea = mono(8);
    private final JTextField secretField = new JTextField(30);
    private final JTextArea privateKeyArea = mono(5);
    private final CardLayout keyCards = new CardLayout();
    private final JPanel keyPanel = new JPanel(keyCards);
    private final JTextArea tokenArea = mono(4);

    /**
     * @param openInVerifier receives the token and, for HMAC tokens, the secret (else null)
     */
    public JwtBuilderPanel(BiConsumer<String, String> openInVerifier) {
        super(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        headerArea.setText(HEADER_TEMPLATE);
        payloadArea.setText(PAYLOAD_TEMPLATE);
        tokenArea.setEditable(false);
        tokenArea.setLineWrap(true);

        JPanel algRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        algRow.add(new JLabel("Algorithm:"));
        algRow.add(algorithmBox);
        algRow.add(new JLabel("  (\"alg\" in the header is set from this; \"none\" is never produced)"));

        JPanel json = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 0.35;
        json.add(titled("Header (JSON)", new JScrollPane(headerArea)), c);

        JButton addIat = new JButton("Set iat = now");
        JButton addExp = new JButton("Set iat + exp (1 hour)");
        JPanel payloadBox = titled("Payload (JSON claims)", new JScrollPane(payloadArea));
        JPanel claimButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        claimButtons.add(addIat);
        claimButtons.add(addExp);
        payloadBox.add(claimButtons, BorderLayout.SOUTH);
        c.gridy = 1;
        c.weighty = 0.65;
        json.add(payloadBox, c);

        JPanel hmacCard = new JPanel(new BorderLayout());
        hmacCard.add(labeled("HMAC secret (UTF-8 text):", secretField), BorderLayout.NORTH);
        keyPanel.add(hmacCard, "hmac");
        JPanel pem = new JPanel(new BorderLayout());
        pem.add(new JLabel("Private key (PEM: \"BEGIN PRIVATE KEY\" or \"BEGIN RSA PRIVATE KEY\"):"), BorderLayout.NORTH);
        pem.add(new JScrollPane(privateKeyArea), BorderLayout.CENTER);
        keyPanel.add(pem, "key");
        JPanel keyBox = titled("Signing Key", keyPanel);

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(algRow, BorderLayout.NORTH);
        top.add(json, BorderLayout.CENTER);
        top.add(keyBox, BorderLayout.SOUTH);

        JButton sign = new JButton("Create Token");
        JButton copy = new JButton("Copy");
        JButton verify = new JButton("Open in Verifier");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(sign);
        buttons.add(copy);
        buttons.add(verify);
        JPanel bottom = titled("Token", new JScrollPane(tokenArea));
        bottom.add(buttons, BorderLayout.SOUTH);

        add(top, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        algorithmBox.addActionListener(e -> keyCards.show(keyPanel,
                JwtSigner.isHmac((String) algorithmBox.getSelectedItem()) ? "hmac" : "key"));
        addIat.addActionListener(e -> setTimes(0));
        addExp.addActionListener(e -> setTimes(3600));
        sign.addActionListener(e -> sign());
        copy.addActionListener(e -> {
            tokenArea.selectAll();
            tokenArea.copy();
            tokenArea.select(0, 0);
        });
        verify.addActionListener(e -> {
            if (tokenArea.getText().isEmpty()) {
                error("Create a token first.");
                return;
            }
            String alg = (String) algorithmBox.getSelectedItem();
            openInVerifier.accept(tokenArea.getText(), JwtSigner.isHmac(alg) ? secretField.getText() : null);
        });
    }

    private void setTimes(long expSeconds) {
        try {
            payloadArea.setText(JwtSigner.withTimeClaims(payloadArea.getText(), Instant.now(), expSeconds));
        } catch (IllegalArgumentException ex) {
            error(ex.getMessage());
        }
    }

    private void sign() {
        String alg = (String) algorithmBox.getSelectedItem();
        try {
            String token = JwtSigner.isHmac(alg)
                    ? JwtSigner.signHmac(headerArea.getText(), payloadArea.getText(), alg,
                            secretField.getText().getBytes(StandardCharsets.UTF_8))
                    : JwtSigner.signWithKey(headerArea.getText(), payloadArea.getText(), alg,
                            PemPrivateKeys.parse(privateKeyArea.getText()));
            tokenArea.setText(token);
            tokenArea.setCaretPosition(0);
            // The secret / private key is never recorded.
            String header = headerArea.getText();
            String payload = payloadArea.getText();
            SessionHistory.global().record("JWT Builder", "Create " + alg,
                    "header:\n" + header + "\n\npayload:\n" + payload, token, () -> {
                        algorithmBox.setSelectedItem(alg);
                        headerArea.setText(header);
                        payloadArea.setText(payload);
                        tokenArea.setText("");
                    });
        } catch (Exception ex) {
            tokenArea.setText("");
            error(ex.getMessage());
        }
    }

    private void error(String message) {
        JOptionPane.showMessageDialog(this, message, "JWT Builder", JOptionPane.ERROR_MESSAGE);
    }

    private static JTextArea mono(int rows) {
        JTextArea a = new JTextArea(rows, 60);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return a;
    }

    private static JPanel titled(String title, Component inner) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(inner, BorderLayout.CENTER);
        return p;
    }

    private static JPanel labeled(String label, JComponent field) {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(new JLabel(label), BorderLayout.NORTH);
        p.add(field, BorderLayout.CENTER);
        return p;
    }
}
