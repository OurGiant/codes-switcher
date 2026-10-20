package com.ourgiant.crypt;

import com.ourgiant.crypt.gpg.GpgKey;
import com.ourgiant.crypt.gpg.GpgOperations;
import com.ourgiant.crypt.gpg.GpgVerifyResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** The Encrypt, Sign, Verify and Keys tabs of the GPG window. All gpg work runs off the event thread. */
final class GpgPanels {

    private GpgPanels() {
    }

    /** Shared plumbing: the GPG window's log, status line, and key cache. */
    static final class Context {
        final GpgOperations gpg;
        final Consumer<String> log;
        final Consumer<String> status;
        final List<Runnable> keyListeners = new ArrayList<>();
        List<GpgKey> publicKeys = List.of();
        List<GpgKey> secretKeys = List.of();

        Context(GpgOperations gpg, Consumer<String> log, Consumer<String> status) {
            this.gpg = gpg;
            this.log = log;
            this.status = status;
        }

        void refreshKeys() {
            new SwingWorker<List<List<GpgKey>>, Void>() {
                @Override
                protected List<List<GpgKey>> doInBackground() throws Exception {
                    return List.of(gpg.listKeys(false), gpg.listKeys(true));
                }

                @Override
                protected void done() {
                    try {
                        publicKeys = get().get(0);
                        secretKeys = get().get(1);
                    } catch (Exception e) {
                        log.accept("Couldn't list keys: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
                    }
                    keyListeners.forEach(Runnable::run);
                }
            }.execute();
        }

        /** Runs {@code task} in the background; its messages go to the log; {@code after} gets the result on the EDT. */
        <T> void run(JButton button, String busy, Callable<T> task, Consumer<T> after) {
            button.setEnabled(false);
            status.accept(busy);
            new SwingWorker<T, Void>() {
                @Override
                protected T doInBackground() throws Exception {
                    return task.call();
                }

                @Override
                protected void done() {
                    button.setEnabled(true);
                    try {
                        after.accept(get());
                    } catch (Exception e) {
                        log.accept("ERROR: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()));
                        status.accept("Failed");
                    }
                }
            }.execute();
        }

        /** A listener that forwards gpg messages to the log on the EDT. */
        com.ourgiant.crypt.gpg.GpgProgressListener listener() {
            return m -> SwingUtilities.invokeLater(() -> log.accept(m));
        }
    }

    // ------------------------------------------------------------------ Encrypt

    static final class EncryptPanel extends JPanel {
        final JTextField inputField = new JTextField();
        final JTextField outputField = new JTextField();
        final DefaultListModel<GpgKey> recipientsModel = new DefaultListModel<>();
        final JList<GpgKey> recipientsList = new JList<>(recipientsModel);
        final JTextField keyFilesField = new JTextField();
        final JComboBox<Object> signerBox = new JComboBox<>();
        final JPasswordField passphraseField = new JPasswordField();
        final JCheckBox armorBox = new JCheckBox("ASCII armor (.asc text output)", true);
        final JCheckBox trustBox = new JCheckBox("Trust recipient keys (I've checked their fingerprints)");
        final JButton encryptButton = new JButton("Encrypt File");

        EncryptPanel(Context ctx) {
            super(new BorderLayout(8, 8));
            recipientsList.setVisibleRowCount(4);
            recipientsList.setCellRenderer(keyRenderer());
            keyFilesField.setToolTipText("Public key files to encrypt to without importing them. Separate several with ;");
            trustBox.setToolTipText("Uses gpg --trust-model always. Without it, gpg refuses imported keys you haven't certified.");
            signerBox.setRenderer(keyRenderer());

            Form f = new Form("Encrypt");
            f.fileRow("File to encrypt:", inputField, false, this::suggestOutput);
            f.fileRow("Save encrypted file as:", outputField, true, null);
            JScrollPane recipients = new JScrollPane(recipientsList);
            recipients.setPreferredSize(new Dimension(300, 80));
            recipients.setMinimumSize(new Dimension(200, 80));
            recipientsList.setToolTipText("Ctrl/Cmd-click to choose several recipients");
            f.row("Recipients (keyring):", recipients, null);
            f.fileRow("…or recipient key files:", keyFilesField, false, null);
            f.row("Sign with:", signerBox, null);
            f.row("Signing key passphrase:", passphraseField, null);
            f.row("", armorBox, null);
            f.row("", trustBox, null);
            add(f, BorderLayout.NORTH);
            add(buttonRow(encryptButton), BorderLayout.CENTER);

            armorBox.addActionListener(e -> suggestOutput());
            ctx.keyListeners.add(() -> {
                recipientsModel.clear();
                ctx.publicKeys.stream().filter(k -> k.canEncrypt() && !k.expired() && !k.revoked())
                        .forEach(recipientsModel::addElement);
                signerBox.removeAllItems();
                signerBox.addItem("Don't sign");
                ctx.secretKeys.stream().filter(GpgKey::canSign).forEach(signerBox::addItem);
            });

            encryptButton.addActionListener(e -> {
                if (!requireFile(this, inputField) || !requireOutput(this, outputField)) {
                    return;
                }
                List<String> recipientIds = recipientsList.getSelectedValuesList().stream().map(GpgKey::fingerprint).toList();
                List<String> files = Arrays.stream(keyFilesField.getText().split(";")).map(String::strip)
                        .filter(s -> !s.isEmpty()).toList();
                if (recipientIds.isEmpty() && files.isEmpty()) {
                    message(this, "Select at least one recipient, or choose a recipient's public key file.");
                    return;
                }
                String signer = signerBox.getSelectedItem() instanceof GpgKey k ? k.fingerprint() : null;
                String pass = new String(passphraseField.getPassword());
                String in = inputField.getText().strip();
                String out = outputField.getText().strip();
                ctx.run(encryptButton, "Encrypting…", () -> ctx.gpg.encryptFile(in, out, recipientIds, files,
                        armorBox.isSelected(), trustBox.isSelected(), signer, pass, ctx.listener()), ok -> {
                    ctx.status.accept(ok ? "Encrypted to " + out : "Encryption failed — see log");
                    if (ok) {
                        message(this, "File encrypted.\n\nOutput: " + out);
                    }
                });
            });
        }

        private void suggestOutput() {
            String in = inputField.getText().strip();
            if (!in.isEmpty()) {
                outputField.setText(stripSuffix(in, ".asc", ".gpg") + (armorBox.isSelected() ? ".asc" : ".gpg"));
            }
        }
    }

    // ------------------------------------------------------------------ Sign

    static final class SignPanel extends JPanel {
        final JTextField inputField = new JTextField();
        final JTextField outputField = new JTextField();
        final JComboBox<GpgOperations.SignMode> modeBox = new JComboBox<>(GpgOperations.SignMode.values());
        final JComboBox<Object> signerBox = new JComboBox<>();
        final JPasswordField passphraseField = new JPasswordField();
        final JCheckBox armorBox = new JCheckBox("ASCII armor", true);
        final JButton signButton = new JButton("Sign File");

        SignPanel(Context ctx) {
            super(new BorderLayout(8, 8));
            signerBox.setRenderer(keyRenderer());
            modeBox.setRenderer(new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
                    String label = switch ((GpgOperations.SignMode) v) {
                        case DETACHED -> "Detached signature (separate .sig/.asc file)";
                        case CLEARSIGN -> "Clearsigned text (readable, text files only)";
                        case INLINE -> "Signed file (signature and data together)";
                    };
                    return super.getListCellRendererComponent(l, label, i, s, f);
                }
            });

            Form f = new Form("Sign");
            f.fileRow("File to sign:", inputField, false, this::suggestOutput);
            f.row("Signature type:", modeBox, null);
            f.fileRow("Save as:", outputField, true, null);
            f.row("Sign with:", signerBox, null);
            f.row("Passphrase:", passphraseField, null);
            f.row("", armorBox, null);
            add(f, BorderLayout.NORTH);
            add(buttonRow(signButton), BorderLayout.CENTER);

            modeBox.addActionListener(e -> {
                armorBox.setEnabled(modeBox.getSelectedItem() != GpgOperations.SignMode.CLEARSIGN);
                suggestOutput();
            });
            armorBox.addActionListener(e -> suggestOutput());
            ctx.keyListeners.add(() -> {
                signerBox.removeAllItems();
                signerBox.addItem("Default key");
                ctx.secretKeys.stream().filter(GpgKey::canSign).forEach(signerBox::addItem);
            });

            signButton.addActionListener(e -> {
                if (!requireFile(this, inputField) || !requireOutput(this, outputField)) {
                    return;
                }
                String signer = signerBox.getSelectedItem() instanceof GpgKey k ? k.fingerprint() : null;
                String pass = new String(passphraseField.getPassword());
                String in = inputField.getText().strip();
                String out = outputField.getText().strip();
                GpgOperations.SignMode mode = (GpgOperations.SignMode) modeBox.getSelectedItem();
                ctx.run(signButton, "Signing…", () -> ctx.gpg.signFile(in, out, mode, armorBox.isSelected(), signer,
                        pass, ctx.listener()), ok -> {
                    ctx.status.accept(ok ? "Signed: " + out : "Signing failed — see log");
                    if (ok) {
                        message(this, "File signed.\n\nOutput: " + out);
                    }
                });
            });
        }

        private void suggestOutput() {
            String in = inputField.getText().strip();
            if (in.isEmpty()) {
                return;
            }
            GpgOperations.SignMode mode = (GpgOperations.SignMode) modeBox.getSelectedItem();
            outputField.setText(switch (mode) {
                case DETACHED -> in + (armorBox.isSelected() ? ".asc" : ".sig");
                case CLEARSIGN -> in + ".asc";
                case INLINE -> in + (armorBox.isSelected() ? ".asc" : ".gpg");
            });
        }
    }

    // ------------------------------------------------------------------ Verify

    static final class VerifyPanel extends JPanel {
        final JTextField signatureField = new JTextField();
        final JTextField dataField = new JTextField();
        final JButton verifyButton = new JButton("Verify Signature");
        final JLabel verdict = new JLabel(" ");
        final JTextArea details = new JTextArea(5, 40);

        VerifyPanel(Context ctx) {
            super(new BorderLayout(8, 8));
            dataField.setToolTipText("For a detached signature, the file it signs. Leave empty for clearsigned or signed files.");
            Form f = new Form("Verify");
            f.fileRow("Signature or signed file:", signatureField, false, this::guessDataFile);
            f.fileRow("Signed data (detached only):", dataField, false, null);
            add(f, BorderLayout.NORTH);

            verdict.setFont(verdict.getFont().deriveFont(Font.BOLD, 15f));
            details.setEditable(false);
            details.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JPanel result = new JPanel(new BorderLayout(4, 4));
            result.setBorder(new TitledBorder("Result"));
            result.add(verdict, BorderLayout.NORTH);
            result.add(details, BorderLayout.CENTER);
            JPanel center = new JPanel(new BorderLayout());
            center.add(buttonRow(verifyButton), BorderLayout.NORTH);
            center.add(result, BorderLayout.CENTER);
            add(center, BorderLayout.CENTER);

            verifyButton.addActionListener(e -> {
                if (!requireFile(this, signatureField)) {
                    return;
                }
                String data = dataField.getText().strip();
                if (!data.isEmpty() && !Files.isRegularFile(Path.of(data))) {
                    message(this, "The signed data file doesn't exist.");
                    return;
                }
                String sig = signatureField.getText().strip();
                ctx.run(verifyButton, "Verifying…", () -> ctx.gpg.verifySignature(sig, data, ctx.listener()), r -> {
                    show(r);
                    ctx.status.accept("Verification: " + r.status());
                });
            });
        }

        void show(GpgVerifyResult r) {
            String who = r.signer() != null ? r.signer() : "key " + r.keyId();
            String text;
            Color color;
            switch (r.status()) {
                case GOOD -> { text = "✔ Good signature from " + who; color = new Color(46, 125, 50); }
                case GOOD_EXPIRED_KEY -> { text = "⚠ Valid signature, but the signing key has expired: " + who; color = new Color(230, 126, 34); }
                case GOOD_REVOKED_KEY -> { text = "⚠ Valid signature, but the signing key was REVOKED: " + who; color = new Color(198, 40, 40); }
                case BAD -> { text = "✘ BAD signature — the file was modified or isn't what was signed"; color = new Color(198, 40, 40); }
                case NO_PUBLIC_KEY -> { text = "? Can't check: signer's public key " + r.keyId() + " isn't in your keyring (import it in Keys)"; color = new Color(230, 126, 34); }
                default -> { text = "✘ " + (r.detail() != null ? r.detail() : "Verification failed — see log"); color = new Color(198, 40, 40); }
            }
            verdict.setText(text);
            verdict.setForeground(color);
            StringBuilder d = new StringBuilder();
            if (r.fingerprint() != null) {
                d.append("Fingerprint: ").append(r.fingerprint()).append('\n');
            }
            if (r.signedAt() != null) {
                d.append("Signed at:   ").append(DateTimeFormatter.ISO_INSTANT.format(r.signedAt())).append('\n');
            }
            if (r.trust() != null) {
                d.append("Key trust:   ").append(r.trust());
                if (r.good() && ("UNDEFINED".equals(r.trust()) || "NEVER".equals(r.trust()))) {
                    d.append("  (the signature is valid, but you haven't confirmed this key belongs to the signer)");
                }
                d.append('\n');
            }
            details.setText(d.toString());
        }

        private void guessDataFile() {
            String sig = signatureField.getText().strip();
            for (String ext : new String[]{".sig", ".asc"}) {
                if (sig.endsWith(ext)) {
                    String data = sig.substring(0, sig.length() - ext.length());
                    if (Files.isRegularFile(Path.of(data)) && looksDetached(sig)) {
                        dataField.setText(data);
                    }
                }
            }
        }

        /** Armored clearsigned/inline files carry their own data; binary .sig or "PGP SIGNATURE" blocks don't. */
        private static boolean looksDetached(String sig) {
            try (var in = Files.newInputStream(Path.of(sig))) {
                String head = new String(in.readNBytes(128), java.nio.charset.StandardCharsets.ISO_8859_1);
                return !head.contains("SIGNED MESSAGE") && !head.contains("BEGIN PGP MESSAGE");
            } catch (java.io.IOException e) {
                return false;
            }
        }
    }

    // ------------------------------------------------------------------ Keys

    static final class KeysPanel extends JPanel {
        final KeyTableModel model = new KeyTableModel();
        final JTable table = new JTable(model);
        final JButton refreshButton = new JButton("Refresh");
        final JButton importButton = new JButton("Import Key File…");
        final JButton copyFprButton = new JButton("Copy Fingerprint");

        KeysPanel(Context ctx) {
            super(new BorderLayout(8, 8));
            table.setAutoCreateRowSorter(true);
            table.getColumnModel().getColumn(0).setPreferredWidth(260);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
            buttons.add(refreshButton);
            buttons.add(importButton);
            buttons.add(copyFprButton);
            JScrollPane scroll = new JScrollPane(table);
            scroll.setBorder(new TitledBorder("Your keyring"));
            add(scroll, BorderLayout.CENTER);
            add(buttons, BorderLayout.SOUTH);

            ctx.keyListeners.add(() -> model.setKeys(ctx.publicKeys, ctx.secretKeys));
            refreshButton.addActionListener(e -> ctx.refreshKeys());
            copyFprButton.addActionListener(e -> {
                int row = table.getSelectedRow();
                if (row < 0) {
                    message(this, "Select a key first.");
                    return;
                }
                GpgKey k = model.keys.get(table.convertRowIndexToModel(row));
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(k.fingerprint()), null);
                ctx.status.accept("Copied fingerprint " + k.fingerprint());
            });
            importButton.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser();
                if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
                    return;
                }
                String file = chooser.getSelectedFile().getAbsolutePath();
                importFile(ctx, file);
            });
        }

        void importFile(Context ctx, String file) {
            ctx.log.accept("Importing " + file);
            ctx.run(importButton, "Importing…", () -> ctx.gpg.importKeys(file, ctx.listener()), ok -> {
                ctx.status.accept(ok ? "Key imported" : "Import failed — see log");
                ctx.refreshKeys();
            });
        }
    }

    static final class KeyTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"User ID", "Key ID", "Algorithm", "Created", "Expires", "Use", "Secret"};
        private static final DateTimeFormatter DATE = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneId.systemDefault());
        List<GpgKey> keys = List.of();
        private java.util.Set<String> secretFprs = java.util.Set.of();

        void setKeys(List<GpgKey> pub, List<GpgKey> sec) {
            keys = pub;
            secretFprs = new java.util.HashSet<>(sec.stream().map(GpgKey::fingerprint).toList());
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return keys.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLUMNS[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            GpgKey k = keys.get(r);
            return switch (c) {
                case 0 -> k.primaryUserId() + (k.userIds().size() > 1 ? "  (+" + (k.userIds().size() - 1) + ")" : "");
                case 1 -> k.keyId();
                case 2 -> k.algorithm() + (k.bits() > 0 && !k.algorithm().startsWith("Ed") ? " " + k.bits() : "");
                case 3 -> k.created() != null ? DATE.format(k.created()) : "";
                case 4 -> k.revoked() ? "REVOKED" : k.expires() == null ? "never"
                        : DATE.format(k.expires()) + (k.expired() ? " (expired)" : "");
                case 5 -> (k.canSign() ? "sign " : "") + (k.canEncrypt() ? "encrypt" : "");
                default -> secretFprs.contains(k.fingerprint()) ? "yes" : "";
            };
        }
    }

    // ------------------------------------------------------------------ helpers

    /** A titled grid form: label | field | optional Browse button. */
    private static final class Form extends JPanel {
        private int row;

        Form(String title) {
            super(new GridBagLayout());
            setBorder(new TitledBorder(title));
        }

        void row(String label, JComponent field, JComponent extra) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4, 5, 4, 5);
            c.gridy = row++;
            c.anchor = GridBagConstraints.WEST;
            add(new JLabel(label), c);
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            add(field, c);
            if (extra != null) {
                c.gridx = 2;
                c.weightx = 0;
                c.fill = GridBagConstraints.NONE;
                add(extra, c);
            }
        }

        void fileRow(String label, JTextField field, boolean save, Runnable onChosen) {
            JButton browse = new JButton("Browse...");
            browse.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser();
                String cur = field.getText().strip();
                if (!cur.isEmpty()) {
                    chooser.setSelectedFile(new File(cur.split(";")[0]));
                }
                int res = save ? chooser.showSaveDialog(this) : chooser.showOpenDialog(this);
                if (res == JFileChooser.APPROVE_OPTION) {
                    field.setText(chooser.getSelectedFile().getAbsolutePath());
                    if (onChosen != null) {
                        onChosen.run();
                    }
                }
            });
            if (onChosen != null) {
                field.addActionListener(e -> onChosen.run());
                field.addFocusListener(new java.awt.event.FocusAdapter() {
                    @Override
                    public void focusLost(java.awt.event.FocusEvent e) {
                        onChosen.run();
                    }
                });
            }
            row(label, field, browse);
        }
    }

    private static JPanel buttonRow(JButton b) {
        b.setFont(new Font("Arial", Font.BOLD, 14));
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
        p.add(b);
        return p;
    }

    private static ListCellRenderer<Object> keyRenderer() {
        return new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
                Object shown = v instanceof GpgKey k ? k.primaryUserId() + "  [" + k.keyId().substring(Math.max(0, k.keyId().length() - 8)) + "]" : v;
                return super.getListCellRendererComponent(l, shown, i, s, f);
            }
        };
    }

    private static boolean requireFile(Component parent, JTextField field) {
        String p = field.getText().strip();
        if (p.isEmpty() || !Files.isRegularFile(Path.of(p))) {
            message(parent, p.isEmpty() ? "Choose a file first." : "File not found: " + p);
            return false;
        }
        return true;
    }

    private static boolean requireOutput(Component parent, JTextField field) {
        if (field.getText().isBlank()) {
            message(parent, "Choose where to save the output.");
            return false;
        }
        Path out = Path.of(field.getText().strip());
        return !Files.exists(out) || JOptionPane.showConfirmDialog(parent, out.getFileName() + " already exists. Replace it?",
                "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION;
    }

    private static String stripSuffix(String s, String... suffixes) {
        for (String x : suffixes) {
            if (s.endsWith(x)) {
                return s.substring(0, s.length() - x.length());
            }
        }
        return s;
    }

    private static void message(Component parent, String text) {
        JOptionPane.showMessageDialog(parent, text, "GPG", JOptionPane.INFORMATION_MESSAGE);
    }
}
