package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/** Runs headless: text components and transfer handlers don't need a display. */
class TextEnhancementsTest {

    @TempDir
    Path dir;

    @Test
    void textAreaLoadsDroppedTextFile() throws Exception {
        Path f = Files.writeString(dir.resolve("note.txt"), "dropped ✓\nline 2");
        JTextArea area = new JTextArea("old");
        assertTrue(TextEnhancements.importFiles(area, List.of(f.toFile())));
        assertEquals("dropped ✓\nline 2", area.getText());
    }

    @Test
    void binaryAndHugeFilesAreRefused() throws Exception {
        Path bin = Files.write(dir.resolve("blob.bin"), new byte[]{0, 1, 2, (byte) 0xff});
        JTextArea area = new JTextArea("keep");
        assertFalse(TextEnhancements.importFiles(area, List.of(bin.toFile())));
        assertEquals("keep", area.getText());

        Path big = dir.resolve("big.txt");
        Files.write(big, "a".repeat((int) TextEnhancements.MAX_TEXT_FILE_BYTES + 1).getBytes());
        assertFalse(TextEnhancements.importFiles(area, List.of(big.toFile())));
        assertEquals("keep", area.getText());
    }

    @Test
    void customHandlerWins() throws Exception {
        List<Path> got = new ArrayList<>();
        JTextArea area = new JTextArea();
        area.putClientProperty(TextEnhancements.FILE_DROP_HANDLER, (Consumer<Path>) got::add);
        Path f = Files.writeString(dir.resolve("x.der"), "x");
        assertTrue(TextEnhancements.importFiles(area, List.of(f.toFile())));
        assertEquals(List.of(f), got);
        assertEquals("", area.getText(), "the tool handles it, not the default loader");
    }

    @Test
    void textFieldGetsPathsAndFiresAction() throws Exception {
        JTextField field = new JTextField();
        int[] actions = {0};
        field.addActionListener(e -> actions[0]++);
        File a = dir.resolve("a.txt").toFile();
        File b = dir.resolve("b.txt").toFile();
        assertTrue(TextEnhancements.importFiles(field, List.of(a, b)));
        assertEquals(a.getAbsolutePath() + ";" + b.getAbsolutePath(), field.getText());
        assertEquals(1, actions[0]);
    }

    @Test
    void pasteStillWorks() {
        JTextArea area = new JTextArea("hello world");
        TextEnhancements.install(area);
        area.select(6, 11);
        TransferHandler.TransferSupport paste = new TransferHandler.TransferSupport(area, new StringSelection("there"));
        assertTrue(area.getTransferHandler().importData(paste));
        assertEquals("hello there", area.getText());
    }

    @Test
    void copyAndCutStillWork() throws Exception {
        JTextArea area = new JTextArea("cut me please");
        TextEnhancements.install(area);
        Clipboard clip = new Clipboard("test");
        area.select(0, 7);
        area.getTransferHandler().exportToClipboard(area, clip, TransferHandler.COPY);
        assertEquals("cut me ", clip.getData(DataFlavor.stringFlavor));
        assertEquals("cut me please", area.getText(), "copy leaves text");
        area.select(0, 7);
        area.getTransferHandler().exportToClipboard(area, clip, TransferHandler.MOVE);
        assertEquals("please", area.getText(), "cut removes the selection");
    }

    @Test
    void readOnlyOutputsRefuseDrops() {
        JTextArea out = new JTextArea("result");
        out.setEditable(false);
        TextEnhancements.install(out);
        TransferHandler.TransferSupport paste = new TransferHandler.TransferSupport(out, new StringSelection("x"));
        assertFalse(out.getTransferHandler().canImport(paste));
        assertEquals(TransferHandler.COPY, out.getTransferHandler().getSourceActions(out));
    }

    @Test
    void passwordsAndNumberFieldsAreSkipped() {
        JPasswordField pw = new JPasswordField();
        TransferHandler before = pw.getTransferHandler();
        TextEnhancements.install(pw);
        assertSame(before, pw.getTransferHandler());
        JFormattedTextField num = new JFormattedTextField(42);
        TransferHandler numBefore = num.getTransferHandler();
        TextEnhancements.install(num);
        assertSame(numBefore, num.getTransferHandler());
    }

    @Test
    void installAllWalksTheTreeOnceAndSetsHints() {
        JPanel root = new JPanel();
        JTextArea area = new JTextArea();
        JPanel inner = new JPanel();
        JTextField field = new JTextField();
        inner.add(field);
        root.add(new JScrollPane(area));
        root.add(inner);
        TextEnhancements.installAll(root);
        TransferHandler h = area.getTransferHandler();
        assertTrue(h instanceof TextEnhancements.Handler);
        assertTrue(field.getTransferHandler() instanceof TextEnhancements.Handler);
        assertNotNull(area.getClientProperty("JTextField.placeholderText"));
        TextEnhancements.installAll(root);
        assertSame(h, area.getTransferHandler(), "second install is a no-op");
    }

    @Test
    void contextMenuMatchesState() {
        JTextArea area = new JTextArea("abc");
        JPopupMenu menu = TextEnhancements.menuFor(area);
        assertEquals(List.of("Cut", "Copy", "Paste", "Select All", "Copy All As"), labels(menu));
        assertFalse(item(menu, "Copy").isEnabled(), "nothing selected");
        area.select(0, 1);
        menu = TextEnhancements.menuFor(area);
        assertTrue(item(menu, "Copy").isEnabled());
        JMenu copyAs = (JMenu) item(menu, "Copy Selection As");
        assertEquals(CopyFormat.values().length, copyAs.getItemCount());

        area.setEditable(false);
        assertEquals(List.of("Copy", "Select All", "Copy Selection As"), labels(TextEnhancements.menuFor(area)));
    }

    private static List<String> labels(JPopupMenu m) {
        return Arrays.stream(m.getComponents()).filter(c -> c instanceof JMenuItem)
                .map(c -> ((JMenuItem) c).getText()).toList();
    }

    private static JMenuItem item(JPopupMenu m, String label) {
        return (JMenuItem) Arrays.stream(m.getComponents())
                .filter(c -> c instanceof JMenuItem i && i.getText().equals(label)).findFirst().orElseThrow();
    }
}
