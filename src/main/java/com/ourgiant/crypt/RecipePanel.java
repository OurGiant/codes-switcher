package com.ourgiant.crypt;

import com.ourgiant.crypt.Recipe.Direction;
import com.ourgiant.crypt.Recipe.Step;
import com.ourgiant.crypt.Recipe.StepResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Encoder/Decoder tab that runs several Text Codecs steps in a row and shows each step's output. */
public class RecipePanel extends JPanel {

    private final DefaultListModel<Step> stepsModel = new DefaultListModel<>();
    private final JList<Step> stepsList = new JList<>(stepsModel);
    private final JComboBox<Direction> directionBox = new JComboBox<>(Direction.values());
    private final JComboBox<String> methodBox = new JComboBox<>(TextCodec.METHODS.toArray(String[]::new));
    private final JTextArea inputArea = mono(true);
    private final JTextArea resultsArea = mono(false);
    private String finalOutput = "";

    public RecipePanel() {
        super(new BorderLayout(10, 10));

        directionBox.setSelectedItem(Direction.DECODE);
        directionBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
                return super.getListCellRendererComponent(l, v == Direction.ENCODE ? "Encode" : "Decode", i, s, f);
            }
        });
        JButton add = new JButton("Add Step");
        JPanel builder = new JPanel(new FlowLayout(FlowLayout.LEFT));
        builder.add(directionBox);
        builder.add(methodBox);
        builder.add(add);
        builder.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));

        stepsList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
                return super.getListCellRendererComponent(l, (i + 1) + ". " + v, i, s, f);
            }
        });
        stepsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JButton up = new JButton("▲");
        JButton down = new JButton("▼");
        JButton remove = new JButton("Remove");
        JButton copyRecipe = new JButton("Copy Recipe");
        JButton loadRecipe = new JButton("Load Recipe…");
        up.setToolTipText("Move step up");
        down.setToolTipText("Move step down");
        copyRecipe.setToolTipText("Copy the steps as text to share or save");
        JPanel stepButtons = new JPanel(new GridLayout(0, 1, 4, 4));
        for (JButton b : new JButton[]{up, down, remove, copyRecipe, loadRecipe}) {
            stepButtons.add(b);
        }
        JPanel stepsPanel = new JPanel(new BorderLayout(6, 6));
        stepsPanel.setBorder(new TitledBorder("Steps"));
        stepsPanel.add(new JScrollPane(stepsList), BorderLayout.CENTER);
        JPanel buttonHolder = new JPanel(new BorderLayout());
        buttonHolder.add(stepButtons, BorderLayout.NORTH);
        stepsPanel.add(buttonHolder, BorderLayout.EAST);
        stepsPanel.setPreferredSize(new Dimension(330, 0));

        JPanel io = new JPanel(new GridLayout(2, 1, 10, 10));
        io.add(titled("Input", inputArea));
        io.add(titled("Output of each step", resultsArea));

        JPanel center = new JPanel(new BorderLayout(10, 10));
        center.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        center.add(stepsPanel, BorderLayout.WEST);
        center.add(io, BorderLayout.CENTER);

        JButton run = new JButton("Run Recipe");
        JButton copyOut = new JButton("Copy Final Output");
        JButton clear = new JButton("Clear All");
        styleButton(run, new Color(76, 175, 80));
        styleButton(copyOut, new Color(156, 39, 176));
        styleButton(clear, new Color(244, 67, 54));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        buttons.add(run);
        buttons.add(copyOut);
        buttons.add(clear);

        add(builder, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        add.addActionListener(e -> addStep());
        remove.addActionListener(e -> {
            int i = stepsList.getSelectedIndex();
            if (i >= 0) {
                stepsModel.remove(i);
                stepsList.setSelectedIndex(Math.min(i, stepsModel.size() - 1));
            }
        });
        up.addActionListener(e -> move(-1));
        down.addActionListener(e -> move(1));
        copyRecipe.addActionListener(e -> copy(recipe().toText()));
        loadRecipe.addActionListener(e -> loadRecipe());
        run.addActionListener(e -> runRecipe());
        copyOut.addActionListener(e -> {
            if (finalOutput.isEmpty()) {
                message("Run the recipe first.");
            } else {
                copy(finalOutput);
            }
        });
        clear.addActionListener(e -> {
            stepsModel.clear();
            inputArea.setText("");
            resultsArea.setText("");
            finalOutput = "";
        });
    }

    private void addStep() {
        try {
            stepsModel.addElement(new Step((Direction) directionBox.getSelectedItem(), (String) methodBox.getSelectedItem()));
            stepsList.setSelectedIndex(stepsModel.size() - 1);
        } catch (IllegalArgumentException ex) {
            message(ex.getMessage());
        }
    }

    private void move(int delta) {
        int i = stepsList.getSelectedIndex();
        int j = i + delta;
        if (i < 0 || j < 0 || j >= stepsModel.size()) {
            return;
        }
        List<Step> items = new ArrayList<>(Collections.list(stepsModel.elements()));
        Collections.swap(items, i, j);
        stepsModel.clear();
        items.forEach(stepsModel::addElement);
        stepsList.setSelectedIndex(j);
    }

    private Recipe recipe() {
        return new Recipe(Collections.list(stepsModel.elements()));
    }

    private void loadRecipe() {
        JTextArea area = mono(true);
        area.setRows(8);
        area.setColumns(36);
        area.setText(recipe().toText());
        int ok = JOptionPane.showConfirmDialog(this, new JScrollPane(area),
                "Paste a recipe (one \"encode|decode <method>\" per line)", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        try {
            Recipe r = Recipe.parse(area.getText());
            stepsModel.clear();
            r.steps().forEach(stepsModel::addElement);
        } catch (IllegalArgumentException ex) {
            message(ex.getMessage());
        }
    }

    private void runRecipe() {
        if (stepsModel.isEmpty()) {
            message("Add at least one step.");
            return;
        }
        List<StepResult> results = recipe().run(inputArea.getText());
        StringBuilder sb = new StringBuilder();
        finalOutput = "";
        for (int i = 0; i < results.size(); i++) {
            StepResult r = results.get(i);
            sb.append("── ").append(i + 1).append(". ").append(r.step()).append(r.ok() ? " ──\n" : "  ✘ FAILED ──\n");
            sb.append(r.ok() ? r.output() : "Error: " + r.error()).append("\n\n");
            if (r.ok()) {
                finalOutput = r.output();
            }
        }
        if (results.size() == stepsModel.size() && results.get(results.size() - 1).ok()) {
            sb.append("✔ All ").append(results.size()).append(" steps succeeded.");
        } else {
            finalOutput = "";
            sb.append("Stopped at step ").append(results.size()).append(".");
            stepsList.setSelectedIndex(results.size() - 1);
        }
        resultsArea.setText(sb.toString());
        resultsArea.setCaretPosition(0);
    }

    private static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private void message(String text) {
        JOptionPane.showMessageDialog(this, text, "Recipe", JOptionPane.INFORMATION_MESSAGE);
    }

    private static JTextArea mono(boolean editable) {
        JTextArea a = new JTextArea(6, 30);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setLineWrap(true);
        a.setEditable(editable);
        return a;
    }

    private static JPanel titled(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private static void styleButton(JButton button, Color color) {
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setFont(new Font("Arial", Font.BOLD, 12));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }
}
