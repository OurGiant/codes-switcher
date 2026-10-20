package com.ourgiant.crypt;

import com.ourgiant.crypt.crypto.classic.BookCipher;
import com.ourgiant.crypt.crypto.classic.ClassicCiphers;
import com.ourgiant.crypt.crypto.classic.Enigma;
import com.ourgiant.crypt.crypto.classic.Enigma.Reflector;
import com.ourgiant.crypt.crypto.classic.Enigma.Rotor;
import com.ourgiant.crypt.crypto.classic.VigenereCracker;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;

/**
 * The Classic Ciphers screens: Enigma, a book cipher, Atbash/Caesar/Vigenère and a Vigenère
 * cracker. For puzzles, CTFs and learning, not for protecting real secrets. Like the rest of
 * the app, history keeps the text and the operation but never the key settings.
 */
final class ClassicCipherPanels {

    static final String ENIGMA = "Enigma";
    static final String BOOK = "Book Cipher";
    static final String SUBSTITUTION = "Substitution";
    static final String CRACKER = "Vigenère Cracker";

    private static final String NOT_SECURE = "For puzzles, CTFs and learning; these ciphers don't protect real secrets.";

    static final String BARBAROSSA = "EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT "
            + "TDEIS MDICA GYKUA CTCDO MOHWX MUUIA UBSTS LRNBZ SZWNR FXWFY SSXJZ VIJHI DISHP RKLKA YUPAD TXQSP INQMA "
            + "TLPIF SVKDA SCTAC DPBOP VHJK";

    private ClassicCipherPanels() {
    }

    static List<ScreenHost.Screen> create() {
        return List.of(new ScreenHost.Screen(ENIGMA, new EnigmaPanel()),
                new ScreenHost.Screen(BOOK, new BookPanel()),
                new ScreenHost.Screen(SUBSTITUTION, new SubstitutionPanel()),
                new ScreenHost.Screen(CRACKER, new CrackerPanel()));
    }

    // ------------------------------------------------------------------ Enigma

    static final class EnigmaPanel extends JPanel {
        final JComboBox<Reflector> reflector = new JComboBox<>(Reflector.values());
        final JComboBox<Rotor> left = new JComboBox<>(Rotor.values());
        final JComboBox<Rotor> middle = new JComboBox<>(Rotor.values());
        final JComboBox<Rotor> right = new JComboBox<>(Rotor.values());
        final JTextField rings = new JTextField("01 01 01", 10);
        final JTextField start = new JTextField("AAA", 10);
        final JTextField plugboard = new JTextField(30);
        final JCheckBox keepOther = new JCheckBox("Keep spaces and punctuation", true);
        final JCheckBox groups = new JCheckBox("Group output in fives (drops them)");
        final JTextArea input = area(true);
        final JTextArea output = area(false);
        final JLabel[] windows = {window(), window(), window()};
        final JLabel status = new JLabel(" ");
        final JButton runButton = new JButton("Encrypt / Decrypt");
        final JButton advanceButton = new JButton("Use as Start");
        final JButton exampleButton = new JButton("Load Example");

        EnigmaPanel() {
            super(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            middle.setSelectedItem(Rotor.II);
            right.setSelectedItem(Rotor.III);
            plugboard.putClientProperty("JTextField.placeholderText", "Up to 13 pairs, e.g. AV BS CG");
            input.putClientProperty("JTextField.placeholderText", "Plaintext or ciphertext: the same settings turn one into the other");

            JPanel rotorRow = flow();
            rotorRow.add(new JLabel("Reflector"));
            rotorRow.add(reflector);
            rotorRow.add(Box.createHorizontalStrut(12));
            for (Object o : new Object[]{"Left", left, "Middle", middle, "Right", right}) {
                rotorRow.add(o instanceof String s ? new JLabel(s) : (JComponent) o);
            }
            JPanel options = flow();
            options.add(keepOther);
            options.add(groups);

            Form f = new Form("Machine (Enigma I / M3)");
            f.row("Rotors:", rotorRow);
            f.row("Rings:", hinted(rings, "Ringstellung, left to right: 01–26 or A–Z"));
            f.row("Start:", hinted(start, "Grundstellung: window letters, left to right"));
            f.row("Plugboard:", plugboard);
            f.row("Options:", options);

            JPanel windowRow = new JPanel(new GridBagLayout());
            for (JLabel w : windows) {
                GridBagConstraints gc = new GridBagConstraints();
                gc.insets = new Insets(0, 4, 0, 4);
                windowRow.add(w, gc);
            }
            JPanel windowBox = new JPanel(new BorderLayout());
            windowBox.setBorder(new TitledBorder("Rotor windows"));
            windowBox.add(windowRow, BorderLayout.CENTER);
            JLabel windowNote = new JLabel("After the last key press", SwingConstants.CENTER);
            windowNote.setForeground(UIManager.getColor("Label.disabledForeground"));
            windowBox.add(windowNote, BorderLayout.SOUTH);
            windowBox.setPreferredSize(new Dimension(220, 10));

            JPanel top = new JPanel(new BorderLayout(10, 0));
            top.add(f, BorderLayout.CENTER);
            top.add(windowBox, BorderLayout.EAST);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            buttons.add(exampleButton);
            buttons.add(advanceButton);
            buttons.add(runButton);
            add(top, BorderLayout.NORTH);
            add(inOut(input, output), BorderLayout.CENTER);
            JPanel south = bottom(status, buttons);
            south.add(note("Rotors I–VIII (VI–VIII turn over at Z and M), with the middle rotor's double step. "
                    + "Only A–Z go through the machine. " + NOT_SECURE), BorderLayout.SOUTH);
            add(south, BorderLayout.SOUTH);

            advanceButton.setToolTipText("Copy the rotor windows into Start, to carry on where this message ended");
            exampleButton.setToolTipText("A real 1941 message (Operation Barbarossa) with its settings");
            runButton.addActionListener(e -> run());
            advanceButton.addActionListener(e -> start.setText(windowText()));
            exampleButton.addActionListener(e -> loadExample());
            keepOther.addActionListener(e -> groups.setSelected(groups.isSelected() && !keepOther.isSelected()));
            groups.addActionListener(e -> keepOther.setSelected(keepOther.isSelected() && !groups.isSelected()));
            showWindows("AAA");
        }

        private Enigma machine() {
            return new Enigma(List.of((Rotor) left.getSelectedItem(), (Rotor) middle.getSelectedItem(),
                    (Rotor) right.getSelectedItem()), (Reflector) reflector.getSelectedItem(),
                    Enigma.parseRings(rings.getText()), start.getText(), plugboard.getText());
        }

        void run() {
            String text = input.getText();
            if (text.isBlank()) {
                message(this, "Type or paste some text first.");
                return;
            }
            Enigma machine;
            try {
                machine = machine();
            } catch (IllegalArgumentException e) {
                message(this, e.getMessage());
                return;
            }
            String from = machine.positions();
            String result = machine.process(text, keepOther.isSelected(), groups.isSelected());
            showOutput(result);
            showWindows(machine.positions());
            long letters = result.chars().filter(Character::isLetter).count();
            status.setText(letters + " letters · windows " + from + " → " + machine.positions());
            SessionHistory.global().record(ENIGMA, "Encrypt / decrypt (" + letters + " letters)", text, result, () -> {
                input.setText(text);
                showOutput("");
            });
        }

        private void loadExample() {
            reflector.setSelectedItem(Reflector.B);
            left.setSelectedItem(Rotor.II);
            middle.setSelectedItem(Rotor.IV);
            right.setSelectedItem(Rotor.V);
            rings.setText("02 21 12");
            start.setText("BLA");
            plugboard.setText("AV BS CG DL FU HZ IN KM OW RX");
            groups.setSelected(true);
            keepOther.setSelected(false);
            input.setText(BARBAROSSA);
            input.setCaretPosition(0);
            showOutput("");
            status.setText("Operation Barbarossa, 1941 (part 1). Press Encrypt / Decrypt to read it.");
        }

        private void showWindows(String letters) {
            for (int i = 0; i < 3; i++) {
                windows[i].setText(String.valueOf(letters.charAt(i)));
            }
        }

        private String windowText() {
            return windows[0].getText() + windows[1].getText() + windows[2].getText();
        }

        private void showOutput(String text) {
            output.setText(text);
            output.setCaretPosition(0);
        }

        private static JLabel window() {
            JLabel l = new JLabel("A", SwingConstants.CENTER) {
                @Override
                public void updateUI() {
                    super.updateUI(); // follow the theme
                    setBackground(UIManager.getColor("TextField.background"));
                    setBorder(BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor"), 2, true));
                }
            };
            l.setFont(new Font(Font.MONOSPACED, Font.BOLD, 28));
            l.setPreferredSize(new Dimension(46, 52));
            l.setOpaque(true);
            return l;
        }
    }

    // ------------------------------------------------------------------ Book cipher

    static final class BookPanel extends JPanel {
        final JTextArea book = area(true);
        final JTextArea message = area(true);
        final JTextArea output = area(false);
        final JRadioButton wordMode = new JRadioButton("Words (line-word)", true);
        final JRadioButton letterMode = new JRadioButton("Letters (line-word-letter)");
        final JLabel bookInfo = new JLabel(" ");
        final JLabel status = new JLabel(" ");
        final JButton loadButton = new JButton("Load Book…");
        final JButton encodeButton = new JButton("Encode");
        final JButton decodeButton = new JButton("Decode");
        private final java.util.random.RandomGenerator random = new SecureRandom();

        BookPanel() {
            super(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            book.setLineWrap(false);
            book.putClientProperty("JTextField.placeholderText", "Paste or load the book: any text both sides have");
            message.putClientProperty("JTextField.placeholderText", "A message to encode, or codes such as 12-4 3-7 to decode");
            ButtonGroup g = new ButtonGroup();
            g.add(wordMode);
            g.add(letterMode);

            JPanel bookBox = new JPanel(new BorderLayout(4, 4));
            bookBox.setBorder(new TitledBorder("Book"));
            bookBox.add(new JScrollPane(book), BorderLayout.CENTER);
            JPanel bookBar = new JPanel(new BorderLayout());
            bookBar.add(bookInfo, BorderLayout.CENTER);
            bookBar.add(loadButton, BorderLayout.EAST);
            bookBox.add(bookBar, BorderLayout.SOUTH);

            JPanel modeRow = flow();
            modeRow.add(new JLabel("Encode as:"));
            modeRow.add(wordMode);
            modeRow.add(letterMode);

            JPanel right = new JPanel(new GridLayout(2, 1, 0, 10));
            right.add(titled("Message or codes", message));
            right.add(titled("Output", output));
            JPanel rightBox = new JPanel(new BorderLayout(0, 4));
            rightBox.add(modeRow, BorderLayout.NORTH);
            rightBox.add(right, BorderLayout.CENTER);

            JPanel center = new JPanel(new GridLayout(1, 2, 10, 0));
            center.add(bookBox);
            center.add(rightBox);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            buttons.add(encodeButton);
            buttons.add(decodeButton);
            JLabel note = note("Lines and words count from 1; case and punctuation around words are ignored. "
                    + "Each encoding picks a random place in the book, so repeated words get different codes. " + NOT_SECURE);
            JPanel south = bottom(status, buttons);
            south.add(note, BorderLayout.SOUTH);

            add(center, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);

            book.getDocument().addDocumentListener(onChange(this::updateInfo));
            loadButton.addActionListener(e -> loadBook());
            encodeButton.addActionListener(e -> run(true));
            decodeButton.addActionListener(e -> run(false));
            updateInfo();
        }

        private void updateInfo() {
            String text = book.getText();
            if (text.isBlank()) {
                bookInfo.setText("No book yet");
                return;
            }
            long lines = text.lines().count();
            long words = text.lines().mapToLong(l -> l.isBlank() ? 0 : l.strip().split("\\s+").length).sum();
            bookInfo.setText(lines + " lines · " + words + " words");
        }

        private void loadBook() {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            try {
                book.setText(Files.readString(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8));
                book.setCaretPosition(0);
            } catch (IOException | RuntimeException e) {
                message(this, "Couldn't read the book: " + e.getMessage());
            }
        }

        void run(boolean encode) {
            String text = message.getText();
            if (text.isBlank()) {
                message(this, encode ? "Type a message to encode." : "Paste the codes to decode.");
                return;
            }
            BookCipher.Mode mode = wordMode.isSelected() ? BookCipher.Mode.WORD : BookCipher.Mode.LETTER;
            String result;
            try {
                BookCipher cipher = new BookCipher(book.getText(), random);
                result = encode ? cipher.encode(text, mode) : cipher.decode(text);
            } catch (IllegalArgumentException e) {
                message(this, e.getMessage());
                return;
            }
            showOutput(result);
            status.setText(encode ? "Encoded " + (mode == BookCipher.Mode.WORD ? "word by word" : "letter by letter") : "Decoded");
            boolean wordSel = wordMode.isSelected();
            SessionHistory.global().record(BOOK, encode ? "Encode · " + (wordSel ? "words" : "letters") : "Decode",
                    text, result, () -> {
                        (wordSel ? wordMode : letterMode).setSelected(true);
                        message.setText(text);
                        showOutput("");
                    });
        }

        private void showOutput(String text) {
            output.setText(text);
            output.setCaretPosition(0);
        }
    }

    // ------------------------------------------------------------------ Atbash / Caesar / Vigenère

    static final class SubstitutionPanel extends JPanel {
        static final String ATBASH = "Atbash";
        static final String CAESAR = "Caesar";
        static final String VIGENERE = "Vigenère";

        final JComboBox<String> method = new JComboBox<>(new String[]{CAESAR, VIGENERE, ATBASH});
        final JSpinner shift = new JSpinner(new SpinnerNumberModel(3, -999, 999, 1));
        final JTextField keyword = new JTextField(16);
        final JTextArea input = area(true);
        final JTextArea output = area(false);
        final DefaultTableModel tryModel = readOnlyModel("Shift", "Score", "Text");
        final JTable tryTable = new JTable(tryModel);
        final JLabel status = new JLabel(" ");
        final JButton encryptButton = new JButton("Encrypt");
        final JButton decryptButton = new JButton("Decrypt");
        final JButton tryAllButton = new JButton("Try All 26");
        private final JLabel shiftLabel = new JLabel("Shift:");
        private final JLabel keywordLabel = new JLabel("Keyword:");
        private final JPanel tryBox = new JPanel(new BorderLayout());

        SubstitutionPanel() {
            super(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            keyword.putClientProperty("JTextField.placeholderText", "e.g. LEMON");
            input.putClientProperty("JTextField.placeholderText", "Case, spaces and punctuation stay where they are");

            JPanel controls = flow();
            controls.add(new JLabel("Cipher:"));
            controls.add(method);
            controls.add(Box.createHorizontalStrut(10));
            controls.add(shiftLabel);
            controls.add(shift);
            controls.add(keywordLabel);
            controls.add(keyword);
            controls.add(Box.createHorizontalStrut(10));
            controls.add(tryAllButton);

            tryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            tryTable.getColumnModel().getColumn(0).setPreferredWidth(50);
            tryTable.getColumnModel().getColumn(0).setMaxWidth(70);
            tryTable.getColumnModel().getColumn(1).setPreferredWidth(70);
            tryTable.getColumnModel().getColumn(1).setMaxWidth(90);
            tryTable.getColumnModel().getColumn(2).setPreferredWidth(600);
            tryTable.getSelectionModel().addListSelectionListener(e -> {
                int row = tryTable.getSelectedRow();
                if (!e.getValueIsAdjusting() && row >= 0) {
                    shift.setValue(tryModel.getValueAt(row, 0));
                    showOutput(ClassicCiphers.caesar(input.getText(), -(Integer) tryModel.getValueAt(row, 0)));
                }
            });
            JScrollPane tryScroll = new JScrollPane(tryTable);
            tryBox.setBorder(new TitledBorder("Caesar: all 26 shifts, most English-like first (lower score is better)"));
            tryBox.add(tryScroll, BorderLayout.CENTER);
            tryBox.setPreferredSize(new Dimension(10, 230));

            JPanel center = new JPanel(new BorderLayout(10, 10));
            center.add(inOut(input, output), BorderLayout.CENTER);
            center.add(tryBox, BorderLayout.SOUTH);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            buttons.add(encryptButton);
            buttons.add(decryptButton);
            JPanel south = bottom(status, buttons);
            south.add(note("Atbash swaps A↔Z, B↔Y…; Caesar shifts every letter; Vigenère shifts by each letter of a keyword in turn, "
                    + "and non-letters don't use up keyword letters. " + NOT_SECURE), BorderLayout.SOUTH);

            add(controls, BorderLayout.NORTH);
            add(center, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);

            method.addActionListener(e -> updateMethod());
            encryptButton.addActionListener(e -> run(true));
            decryptButton.addActionListener(e -> run(false));
            tryAllButton.addActionListener(e -> tryAll());
            updateMethod();
        }

        private void updateMethod() {
            String m = (String) method.getSelectedItem();
            boolean caesar = CAESAR.equals(m);
            shiftLabel.setVisible(caesar);
            shift.setVisible(caesar);
            tryAllButton.setVisible(caesar);
            tryBox.setVisible(caesar);
            keywordLabel.setVisible(VIGENERE.equals(m));
            keyword.setVisible(VIGENERE.equals(m));
            encryptButton.setText(ATBASH.equals(m) ? "Encrypt / Decrypt" : "Encrypt");
            decryptButton.setVisible(!ATBASH.equals(m));
            revalidate();
        }

        void run(boolean encrypt) {
            String text = input.getText();
            if (text.isEmpty()) {
                message(this, "Type or paste some text first.");
                return;
            }
            String m = (String) method.getSelectedItem();
            int s = (Integer) shift.getValue();
            String result;
            try {
                result = switch (m) {
                    case ATBASH -> ClassicCiphers.atbash(text);
                    case CAESAR -> ClassicCiphers.caesar(text, encrypt ? s : -s);
                    default -> encrypt ? ClassicCiphers.vigenereEncrypt(text, keyword.getText())
                            : ClassicCiphers.vigenereDecrypt(text, keyword.getText());
                };
            } catch (IllegalArgumentException e) {
                message(this, e.getMessage());
                return;
            }
            showOutput(result);
            String op = ATBASH.equals(m) ? "Atbash" : m + " · " + (encrypt ? "encrypt" : "decrypt");
            status.setText(op);
            record(op, text, result, m);
        }

        void tryAll() {
            String text = input.getText();
            if (text.chars().noneMatch(c -> (c | 0x20) >= 'a' && (c | 0x20) <= 'z')) {
                message(this, "Paste some Caesar ciphertext (with letters) first.");
                return;
            }
            tryModel.setRowCount(0);
            List<ClassicCiphers.CaesarCandidate> all = ClassicCiphers.caesarAll(text);
            for (ClassicCiphers.CaesarCandidate c : all) {
                tryModel.addRow(new Object[]{c.shift(), String.format(Locale.ROOT, "%.1f", c.score()),
                        SessionHistory.preview(c.text(), 200)});
            }
            tryTable.setRowSelectionInterval(0, 0);
            status.setText("Best guess: shift " + all.get(0).shift() + ". Pick another row to see that one.");
            record("Caesar · try all 26", text, output.getText(), CAESAR);
        }

        private void record(String op, String text, String result, String m) {
            SessionHistory.global().record(SUBSTITUTION, op, text, result, () -> {
                method.setSelectedItem(m);
                input.setText(text);
                showOutput("");
            });
        }

        private void showOutput(String text) {
            output.setText(text);
            output.setCaretPosition(0);
        }
    }

    // ------------------------------------------------------------------ Vigenère cracker

    static final class CrackerPanel extends JPanel {
        final JTextArea input = area(true);
        final JTextArea output = area(false);
        final JSpinner maxLength = new JSpinner(new SpinnerNumberModel(20, 1, 40, 1));
        final DefaultTableModel candidateModel = readOnlyModel("#", "Key", "Length", "Score", "Preview");
        final JTable candidates = new JTable(candidateModel);
        final DefaultTableModel lengthModel = readOnlyModel("Length", "IoC", "Kasiski");
        final JTable lengths = new JTable(lengthModel);
        final JLabel status = new JLabel(" ");
        final JButton crackButton = new JButton("Crack");
        private List<VigenereCracker.Candidate> found = List.of();

        CrackerPanel() {
            super(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            input.putClientProperty("JTextField.placeholderText", "Vigenère ciphertext: a few hundred letters of English works best");

            candidates.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            int[] widths = {30, 110, 55, 65, 420};
            for (int i = 0; i < widths.length; i++) {
                candidates.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            }
            candidates.getColumnModel().getColumn(0).setMaxWidth(40);
            candidates.getSelectionModel().addListSelectionListener(e -> {
                int row = candidates.getSelectedRow();
                if (!e.getValueIsAdjusting() && row >= 0 && row < found.size()) {
                    showOutput(found.get(row).plaintext());
                }
            });

            JPanel controls = flow();
            controls.add(new JLabel("Longest key to try:"));
            controls.add(maxLength);
            controls.add(Box.createHorizontalStrut(10));
            controls.add(crackButton);

            JPanel candBox = new JPanel(new BorderLayout());
            candBox.setBorder(new TitledBorder("Candidate keys (lower score is more English-like)"));
            candBox.add(new JScrollPane(candidates), BorderLayout.CENTER);
            JPanel lenBox = new JPanel(new BorderLayout());
            lenBox.setBorder(new TitledBorder("Key lengths"));
            lenBox.add(new JScrollPane(lengths), BorderLayout.CENTER);
            lenBox.setPreferredSize(new Dimension(230, 10));
            lengths.setToolTipText("Average index of coincidence of the columns (English ≈ 0.066, random ≈ 0.038), "
                    + "and how many repeated-trigram distances the length divides");
            JPanel results = new JPanel(new BorderLayout(10, 0));
            results.add(candBox, BorderLayout.CENTER);
            results.add(lenBox, BorderLayout.EAST);
            results.setPreferredSize(new Dimension(10, 230));

            JPanel top = new JPanel(new BorderLayout(0, 4));
            top.add(controls, BorderLayout.NORTH);
            top.add(inOut(input, output), BorderLayout.CENTER);

            JPanel center = new JPanel(new BorderLayout(10, 10));
            center.add(top, BorderLayout.CENTER);
            center.add(results, BorderLayout.SOUTH);

            JPanel south = new JPanel(new BorderLayout());
            south.add(status, BorderLayout.CENTER);
            south.add(note("Finds the key length from the index of coincidence (with Kasiski repeats as a check), "
                    + "then each key letter by chi-square against English letter frequencies. "
                    + "Short or non-English texts may need a few tries."), BorderLayout.SOUTH);

            add(center, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);
            crackButton.addActionListener(e -> crack());
        }

        void crack() {
            String text = input.getText();
            VigenereCracker.Result r;
            try {
                r = VigenereCracker.crack(text, (Integer) maxLength.getValue(), 10);
            } catch (IllegalArgumentException e) {
                message(this, e.getMessage());
                return;
            }
            found = r.candidates();
            candidateModel.setRowCount(0);
            for (int i = 0; i < found.size(); i++) {
                VigenereCracker.Candidate c = found.get(i);
                candidateModel.addRow(new Object[]{i + 1, c.key(), c.key().length(),
                        String.format(Locale.ROOT, "%.1f", c.score()), SessionHistory.preview(c.plaintext(), 200)});
            }
            lengthModel.setRowCount(0);
            for (VigenereCracker.KeyLength kl : r.lengths()) {
                lengthModel.addRow(new Object[]{kl.length(), String.format(Locale.ROOT, "%.4f", kl.ioc()), kl.kasiski()});
            }
            if (!found.isEmpty()) {
                candidates.setRowSelectionInterval(0, 0);
                status.setText(r.letters() + " letters · best key " + found.get(0).key() + " (" + found.get(0).key().length()
                        + " letters). Pick another row to compare.");
            }
            String best = found.isEmpty() ? "" : found.get(0).plaintext();
            SessionHistory.global().record(CRACKER, "Crack (" + r.letters() + " letters)", text, best, () -> {
                input.setText(text);
                showOutput("");
            });
        }

        private void showOutput(String text) {
            output.setText(text);
            output.setCaretPosition(0);
        }
    }

    // ------------------------------------------------------------------ shared bits

    private static JTextArea area(boolean editable) {
        JTextArea a = new JTextArea(6, 30);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setEditable(editable);
        return a;
    }

    private static JPanel titled(String title, JComponent c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(new JScrollPane(c), BorderLayout.CENTER);
        return p;
    }

    private static JPanel inOut(JTextArea input, JTextArea output) {
        JPanel p = new JPanel(new GridLayout(1, 2, 10, 0));
        p.add(titled("Input", input));
        p.add(titled("Output", output));
        return p;
    }

    private static JPanel bottom(JLabel status, JPanel buttons) {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.add(status, BorderLayout.CENTER);
        p.add(buttons, BorderLayout.EAST);
        return p;
    }

    private static JPanel flow() {
        return new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    }

    private static JPanel hinted(JTextField field, String hint) {
        JPanel p = flow();
        p.add(field);
        JLabel l = new JLabel(hint);
        l.setForeground(UIManager.getColor("Label.disabledForeground"));
        p.add(l);
        return p;
    }

    private static JLabel note(String text) {
        JLabel l = new JLabel("<html>" + text + "</html>");
        l.setForeground(UIManager.getColor("Label.disabledForeground"));
        return l;
    }

    private static DefaultTableModel readOnlyModel(String... columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    private static javax.swing.event.DocumentListener onChange(Runnable r) {
        return new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        };
    }

    private static void message(Component parent, String text) {
        JOptionPane.showMessageDialog(parent, text, "Classic Ciphers", JOptionPane.WARNING_MESSAGE);
    }

    /** A titled label | field grid. */
    private static final class Form extends JPanel {
        private int row;

        Form(String title) {
            super(new GridBagLayout());
            setBorder(new TitledBorder(title));
        }

        void row(String label, JComponent field) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 5, 3, 5);
            c.gridy = row++;
            c.anchor = GridBagConstraints.WEST;
            add(new JLabel(label), c);
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            add(field, c);
        }
    }
}
