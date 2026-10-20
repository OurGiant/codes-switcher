package com.ourgiant.crypt;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** The Session → History screen: recent operations, kept in memory only. */
public class HistoryPanel extends JPanel {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final SessionHistory history;
    private final ScreenHost host;
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final JTextArea inputArea = area();
    private final JTextArea outputArea = area();
    private final JButton openButton = new JButton("Open in Tool");
    private final JButton copyButton = new JButton("Copy Output");
    private final JButton clearButton = new JButton("Clear History");
    private final JPanel listCard = new JPanel(new CardLayout());
    private final JLabel emptyNote = new JLabel("Nothing yet. Operations you run appear here.", SwingConstants.CENTER);

    public HistoryPanel(SessionHistory history, ScreenHost host) {
        super(new BorderLayout(8, 8));
        this.history = history;
        this.host = host;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel privacy = new JLabel("Kept in memory only and gone when the app closes. Passwords, secrets and keys are never recorded.");
        privacy.setFont(privacy.getFont().deriveFont(Font.ITALIC));
        privacy.setForeground(UIManager.getColor("Label.disabledForeground"));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        int[] widths = {70, 130, 210, 230, 260};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.getSelectionModel().addListSelectionListener(e -> showSelected());
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    openSelected();
                }
            }
        });

        listCard.add(new JScrollPane(table), "table");
        listCard.add(emptyNote, "empty");

        JPanel details = new JPanel(new GridLayout(1, 2, 8, 8));
        details.add(titled("Input", inputArea));
        details.add(titled("Output", outputArea));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, listCard, details);
        split.setResizeWeight(0.55);
        split.setBorder(null);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(openButton);
        buttons.add(copyButton);
        buttons.add(clearButton);
        openButton.setToolTipText("Go to the tool with this input filled in (passwords and keys need re-entering)");

        JPanel south = new JPanel(new BorderLayout());
        privacy.setBorder(BorderFactory.createEmptyBorder(2, 4, 0, 4));
        south.add(privacy, BorderLayout.NORTH);
        south.add(buttons, BorderLayout.SOUTH);

        add(split, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        openButton.addActionListener(e -> openSelected());
        copyButton.addActionListener(e -> selected().ifPresent(x -> TextEnhancements.copy(x.output())));
        clearButton.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Clear all " + history.entries().size() + " history entries?",
                    "Clear History", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                history.clear();
            }
        });

        Runnable listener = () -> SwingUtilities.invokeLater(this::refresh);
        history.addListener(listener);
        refresh();
    }

    private void refresh() {
        long selectedId = selected().map(SessionHistory.Entry::id).orElse(-1L);
        model.entries = history.entries();
        model.fireTableDataChanged();
        ((CardLayout) listCard.getLayout()).show(listCard, model.entries.isEmpty() ? "empty" : "table");
        for (int i = 0; i < model.entries.size(); i++) {
            if (model.entries.get(i).id() == selectedId) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
        if (!model.entries.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        } else {
            showSelected();
        }
    }

    private java.util.Optional<SessionHistory.Entry> selected() {
        int row = table.getSelectedRow();
        return row >= 0 && row < model.entries.size() ? java.util.Optional.of(model.entries.get(row)) : java.util.Optional.empty();
    }

    private void showSelected() {
        var e = selected();
        inputArea.setText(e.map(SessionHistory.Entry::input).orElse(""));
        outputArea.setText(e.map(SessionHistory.Entry::output).orElse(""));
        inputArea.setCaretPosition(0);
        outputArea.setCaretPosition(0);
        openButton.setEnabled(e.map(SessionHistory.Entry::canRestore).orElse(false));
        openButton.setToolTipText(e.isPresent() && !e.get().canRestore()
                ? "This entry was too large to keep in full, so it can't be reopened"
                : "Go to the tool with this input filled in (passwords and keys need re-entering)");
        copyButton.setEnabled(e.isPresent());
        clearButton.setEnabled(!model.entries.isEmpty());
    }

    private void openSelected() {
        selected().filter(SessionHistory.Entry::canRestore).ifPresent(e -> {
            host.showScreen(e.screen());
            e.restore().run();
        });
    }

    private static final class Model extends AbstractTableModel {
        private static final String[] COLUMNS = {"Time", "Tool", "Operation", "Input", "Output"};
        List<SessionHistory.Entry> entries = List.of();

        @Override
        public int getRowCount() {
            return entries.size();
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
            SessionHistory.Entry e = entries.get(r);
            return switch (c) {
                case 0 -> TIME.format(e.time());
                case 1 -> e.screen();
                case 2 -> e.operation();
                case 3 -> SessionHistory.preview(e.input(), 80);
                default -> SessionHistory.preview(e.output(), 80);
            };
        }
    }

    private static JTextArea area() {
        JTextArea a = new JTextArea(6, 30);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return a;
    }

    private static JPanel titled(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }
}
