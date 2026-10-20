package com.ourgiant.crypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import javax.swing.text.Position;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * App-wide text box improvements, installed on every text component in a screen:
 * <ul>
 *   <li>drop a file onto a text area to load it (or onto a one-line field to fill in its path);</li>
 *   <li>a right-click menu with Cut / Copy / Paste / Select All and "Copy as…";</li>
 *   <li>a hint in empty text areas saying a file can be dropped there.</li>
 * </ul>
 * Password fields are always left alone.
 */
public final class TextEnhancements {
    private static final Logger log = LoggerFactory.getLogger(TextEnhancements.class);

    /** Client property: a {@code Consumer<Path>} that handles a file dropped on this component instead of the default. */
    public static final String FILE_DROP_HANDLER = "codesSwitcher.fileDropHandler";

    private static final String INSTALLED = "codesSwitcher.textEnhanced";
    private static final String PLACEHOLDER = "JTextField.placeholderText"; // FlatLaf; also works on text areas
    static final long MAX_TEXT_FILE_BYTES = 5L * 1024 * 1024;

    private TextEnhancements() {
    }

    /** Installs on every text component under {@code root} that doesn't have it yet. Safe to call repeatedly. */
    public static void installAll(Container root) {
        for (Component c : root.getComponents()) {
            if (c instanceof JTextComponent t) {
                install(t);
            }
            if (c instanceof Container k) {
                installAll(k);
            }
        }
    }

    public static void install(JTextComponent t) {
        // Passwords are never dragged or copied out; formatted fields (spinners) only take numbers.
        if (t instanceof JPasswordField || t instanceof JFormattedTextField
                || Boolean.TRUE.equals(t.getClientProperty(INSTALLED))) {
            return;
        }
        t.putClientProperty(INSTALLED, Boolean.TRUE);
        t.setTransferHandler(new Handler());
        t.addMouseListener(new PopupTrigger());
        if (t instanceof JTextArea area && area.isEditable()) {
            if (area.getClientProperty(PLACEHOLDER) == null) {
                area.putClientProperty(PLACEHOLDER, "Type or paste here, or drop a file");
            }
            addHintOverlay(area);
        }
    }

    /**
     * FlatLaf draws placeholder text only in one-line fields, so for text areas the hint is painted
     * by a {@link JLayer} placed between the scroll pane and the area. Scrolling and line wrap are
     * unchanged because JLayer passes the Scrollable behaviour through to the area.
     */
    private static void addHintOverlay(JTextArea area) {
        if (!(area.getParent() instanceof JViewport viewport)) {
            return;
        }
        JLayer<JTextArea> layer = new JLayer<>(area, new javax.swing.plaf.LayerUI<>() {
            @Override
            public void paint(Graphics g, JComponent c) {
                super.paint(g, c);
                Object hint = area.getClientProperty(PLACEHOLDER);
                if (hint == null || area.getDocument().getLength() > 0 || !area.isEditable()) {
                    return;
                }
                Graphics2D g2 = (Graphics2D) g.create();
                try {
                    g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                    Color color = UIManager.getColor("TextField.placeholderForeground");
                    g2.setColor(color != null ? color : Color.GRAY);
                    Font font = UIManager.getFont("TextField.font");
                    g2.setFont(font != null ? font : area.getFont());
                    Insets in = area.getInsets();
                    g2.drawString(hint.toString(), in.left + 2, in.top + g2.getFontMetrics().getAscent());
                } finally {
                    g2.dispose();
                }
            }
        });
        viewport.setView(layer);
        // The area is opaque and repaints itself directly, so ask the layer to repaint when text changes.
        area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { layer.repaint(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { layer.repaint(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { }
        });
        area.addPropertyChangeListener("document", e -> layer.repaint());
    }

    // ------------------------------------------------------------------ drag and drop / clipboard

    /**
     * Handles files itself and plain text the way Swing's own text handler does. Swing's handler
     * can't be wrapped (its createTransferable is protected), so text export is reimplemented here.
     */
    static final class Handler extends TransferHandler {
        private Position dragStart;
        private Position dragEnd;

        @Override
        public boolean canImport(TransferSupport s) {
            JTextComponent t = (JTextComponent) s.getComponent();
            if (!t.isEditable() || !t.isEnabled()) {
                return false;
            }
            if (s.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                return true;
            }
            return s.isDataFlavorSupported(DataFlavor.stringFlavor);
        }

        @Override
        public boolean importData(TransferSupport s) {
            if (!canImport(s)) {
                return false;
            }
            JTextComponent t = (JTextComponent) s.getComponent();
            try {
                if (s.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                    @SuppressWarnings("unchecked")
                    List<File> files = (List<File>) s.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    return !files.isEmpty() && importFiles(t, files);
                }
                String text = (String) s.getTransferable().getTransferData(DataFlavor.stringFlavor);
                if (s.isDrop() && s.getDropLocation() instanceof JTextComponent.DropLocation loc) {
                    int pos = loc.getIndex();
                    // Dropping a selection back inside itself is a no-op, as in Swing's own handler.
                    if (dragStart != null && pos >= dragStart.getOffset() && pos <= dragEnd.getOffset()) {
                        dragStart = null;
                        return false;
                    }
                    t.getDocument().insertString(pos, text, null);
                    t.select(pos, pos + text.length());
                } else {
                    t.replaceSelection(text);
                }
                return true;
            } catch (Exception e) {
                log.debug("Import into text box failed", e);
                return false;
            }
        }

        @Override
        public int getSourceActions(JComponent c) {
            return c instanceof JTextComponent t && t.isEditable() ? COPY_OR_MOVE : COPY;
        }

        @Override
        protected Transferable createTransferable(JComponent c) {
            JTextComponent t = (JTextComponent) c;
            int start = t.getSelectionStart();
            int end = t.getSelectionEnd();
            if (start == end) {
                return null;
            }
            try {
                dragStart = t.getDocument().createPosition(start);
                dragEnd = t.getDocument().createPosition(end);
            } catch (BadLocationException e) {
                return null;
            }
            return new StringSelection(t.getSelectedText());
        }

        @Override
        protected void exportDone(JComponent source, Transferable data, int action) {
            if (action == MOVE && dragStart != null && source instanceof JTextComponent t && t.isEditable()) {
                try {
                    int start = dragStart.getOffset();
                    int end = dragEnd.getOffset();
                    if (end > start) {
                        t.getDocument().remove(start, end - start);
                    }
                } catch (BadLocationException e) {
                    log.debug("Couldn't remove moved text", e);
                }
            }
            dragStart = null;
            dragEnd = null;
        }
    }

    /** Text area: load the file (or hand it to the tool's own handler). One-line field: fill in the path(s). */
    static boolean importFiles(JTextComponent t, List<File> files) {
        Object custom = t.getClientProperty(FILE_DROP_HANDLER);
        if (custom instanceof Consumer<?> handler) {
            @SuppressWarnings("unchecked")
            Consumer<Path> h = (Consumer<Path>) handler;
            h.accept(files.get(0).toPath());
            return true;
        }
        if (t instanceof JTextField) {
            t.setText(files.stream().map(File::getAbsolutePath).collect(Collectors.joining(";")));
            // Let forms react as if the path had been typed (e.g. to suggest an output name).
            if (t instanceof JTextField f) {
                f.postActionEvent();
            }
            return true;
        }
        Path p = files.get(0).toPath();
        try {
            long size = Files.size(p);
            if (size > MAX_TEXT_FILE_BYTES) {
                message(t, p.getFileName() + " is " + (size >> 20) + " MB, too large to load as text here.");
                return false;
            }
            byte[] data = Files.readAllBytes(p);
            if (!FormatDetector.printable(data) && data.length > 0) {
                message(t, p.getFileName() + " is a binary file. Use Text Codecs (it reads raw bytes) or File Hash.");
                return false;
            }
            t.setText(new String(data, StandardCharsets.UTF_8));
            t.setCaretPosition(0);
            return true;
        } catch (IOException e) {
            message(t, "Couldn't read " + p.getFileName() + ": " + e.getMessage());
            return false;
        }
    }

    private static void message(Component parent, String text) {
        if (GraphicsEnvironment.isHeadless()) {
            log.info(text);
            return;
        }
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(parent, text, "Drop File", JOptionPane.INFORMATION_MESSAGE));
    }

    // ------------------------------------------------------------------ context menu

    private static final class PopupTrigger extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent e) {
            maybeShow(e);
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            maybeShow(e);
        }

        private void maybeShow(MouseEvent e) {
            if (e.isPopupTrigger() && e.getComponent() instanceof JTextComponent t) {
                if (!t.isFocusOwner()) {
                    t.requestFocusInWindow();
                }
                menuFor(t).show(t, e.getX(), e.getY());
            }
        }
    }

    /** The right-click menu for a text box; package-private so tests and the UI driver can inspect it. */
    static JPopupMenu menuFor(JTextComponent t) {
        boolean editable = t.isEditable() && t.isEnabled();
        boolean hasSelection = t.getSelectionStart() != t.getSelectionEnd();
        boolean hasText = t.getDocument().getLength() > 0;

        JPopupMenu menu = new JPopupMenu();
        if (editable) {
            menu.add(item("Cut", hasSelection, t::cut));
        }
        menu.add(item("Copy", hasSelection, t::copy));
        if (editable) {
            menu.add(item("Paste", true, t::paste));
        }
        menu.addSeparator();
        menu.add(item("Select All", hasText, t::selectAll));

        JMenu copyAs = new JMenu("Copy " + (hasSelection ? "Selection" : "All") + " As");
        copyAs.setEnabled(hasText);
        for (CopyFormat f : CopyFormat.values()) {
            copyAs.add(item(f.label(), hasText, () -> copy(f.format(hasSelection ? t.getSelectedText() : t.getText()))));
        }
        menu.add(copyAs);
        return menu;
    }

    private static JMenuItem item(String label, boolean enabled, Runnable action) {
        JMenuItem i = new JMenuItem(label);
        i.setEnabled(enabled);
        i.addActionListener(e -> action.run());
        return i;
    }

    static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
}
