package com.ourgiant.crypt;

import com.ourgiant.crypt.ScreenCatalog.Entry;
import com.ourgiant.crypt.ScreenCatalog.Provider;
import com.ourgiant.crypt.util.UpdateChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The app's single window: a grouped sidebar of every tool screen, the selected screen on the
 * right, and (for GPG screens) the shared GPG log underneath. Tool classes are only created the
 * first time one of their screens is opened.
 */
public class MainWindow extends JFrame implements ScreenHost {
    private static final Logger log = LoggerFactory.getLogger(MainWindow.class);

    private static final int DEFAULT_SIDEBAR_WIDTH = 210;

    /** A sidebar group heading; not selectable. */
    private record Header(String name) {
    }

    private final AppPreferences prefs;
    private final Set<Provider> loaded = EnumSet.noneOf(Provider.class);
    /** One holder per screen; it contains either the screen or a "shown in its own window" note. */
    private final Map<String, JPanel> holders = new HashMap<>();
    private final Map<String, JComponent> contents = new HashMap<>();
    private final Map<String, JFrame> poppedOut = new HashMap<>();

    private final CardLayout cards = new CardLayout();
    private final JPanel cardPanel = new JPanel(cards);
    private final DefaultListModel<Object> navModel = new DefaultListModel<>();
    private final JList<Object> navList = new JList<>(navModel);
    private final JTextField filterField = new JTextField();
    private final JLabel groupLabel = new JLabel(" ");
    private final JLabel titleLabel = new JLabel(" ");
    private final JButton popOutButton = new JButton("Open in New Window");
    private final JPanel footerHolder = new JPanel(new BorderLayout());
    private final JSplitPane split;
    private JComponent gpgFooter;
    private String current;
    private boolean syncingSelection;

    public MainWindow(String initialScreen) {
        this(initialScreen, new AppPreferences());
    }

    MainWindow(String initialScreen, AppPreferences prefs) {
        this.prefs = prefs;
        setTitle("Codes Switcher v" + AppVersion.get());
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setMinimumSize(new Dimension(820, 560));
        Image icon = AppLauncher.loadAppIcon();
        if (icon != null) {
            setIconImage(icon);
        }

        for (Entry e : ScreenCatalog.ENTRIES) {
            JPanel holder = new JPanel(new BorderLayout());
            holders.put(e.title(), holder);
            cardPanel.add(holder, e.title());
        }

        split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildSidebar(), buildContentArea());
        split.setDividerLocation(prefs.getSidebarWidth(DEFAULT_SIDEBAR_WIDTH));
        split.setBorder(null);
        setContentPane(split);
        setJMenuBar(buildMenuBar());
        installShortcuts();
        restoreBounds();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                exit();
            }
        });

        String start = ScreenCatalog.byTitle(initialScreen).isPresent() ? initialScreen
                : ScreenCatalog.byTitle(prefs.getLastScreen()).isPresent() ? prefs.getLastScreen()
                : ScreenCatalog.DEFAULT_SCREEN;
        showScreen(start);
    }

    /** Opens the main window on {@code screen} (a screen title), or on the last-used screen if null/unknown. */
    public static MainWindow open(String screen) {
        MainWindow w = new MainWindow(screen);
        w.setVisible(true);
        w.checkForUpdateAndNotifyIfNewer();
        return w;
    }

    // ------------------------------------------------------------------ ScreenHost

    @Override
    public void showScreen(String title) {
        Optional<Entry> found = ScreenCatalog.byTitle(title);
        if (found.isEmpty()) {
            log.warn("Unknown screen {}", title);
            return;
        }
        Entry entry = found.get();
        ensureLoaded(entry.provider());
        current = title;
        cards.show(cardPanel, title);
        groupLabel.setText(entry.group().toUpperCase());
        titleLabel.setText(entry.label());
        popOutButton.setText(poppedOut.containsKey(title) ? "Bring Back Here" : "Open in New Window");

        footerHolder.removeAll();
        if (entry.provider() == Provider.GPG && gpgFooter != null) {
            footerHolder.add(gpgFooter, BorderLayout.CENTER);
        }
        footerHolder.revalidate();
        footerHolder.repaint();

        selectInSidebar(entry);
        prefs.setLastScreen(title);

        JFrame frame = poppedOut.get(title);
        if (frame != null) {
            frame.toFront();
            frame.requestFocus();
        }
    }

    @Override
    public Component dialogOwner() {
        // A popped-out screen's dialogs belong over that window; anything else (including a
        // pop-out that was just closed but is still reported as active) falls back to this one.
        Window active = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
        return active != null && active.isShowing() && poppedOut.containsValue(active) ? active : this;
    }

    /** The screen currently selected in the sidebar. */
    public String currentScreen() {
        return current;
    }

    // ------------------------------------------------------------------ loading tools

    private void ensureLoaded(Provider provider) {
        if (!loaded.add(provider)) {
            return;
        }
        List<Screen> screens = switch (provider) {
            case CODECS -> new EncodingDecodingApp().detachScreens(this);
            case INSPECTOR -> new CryptoInspectorApp().detachScreens(this);
            case GPG -> {
                GPGDecryptor gpg = new GPGDecryptor();
                List<Screen> s = gpg.detachScreens(this);
                gpgFooter = collapsibleGpgFooter(gpg.detachFooter());
                yield s;
            }
            case STEGO -> StegoPanels.create();
            case HISTORY -> List.of(new Screen("History", new HistoryPanel(SessionHistory.global(), this)));
        };
        for (Screen s : screens) {
            JPanel holder = holders.get(s.title());
            if (holder == null) {
                log.warn("Screen {} isn't in the catalog; skipping", s.title());
                continue;
            }
            JComponent content = s.content();
            content.setBorder(BorderFactory.createCompoundBorder(new EmptyBorder(0, 4, 4, 4), content.getBorder()));
            contents.put(s.title(), content);
            holder.add(content, BorderLayout.CENTER);
            TextEnhancements.installAll(content);
        }
        cardPanel.revalidate();
    }

    private JComponent collapsibleGpgFooter(JComponent footer) {
        BorderLayout layout = (BorderLayout) footer.getLayout();
        Component logPane = layout.getLayoutComponent(BorderLayout.CENTER);
        if (logPane != null) {
            logPane.setPreferredSize(new Dimension(100, 140));
        }
        JToggleButton toggle = new JToggleButton("Hide GPG Log", true);
        toggle.addActionListener(e -> {
            if (logPane != null) {
                logPane.setVisible(toggle.isSelected());
            }
            toggle.setText(toggle.isSelected() ? "Hide GPG Log" : "Show GPG Log");
            footer.revalidate();
        });
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bar.add(toggle);
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(new EmptyBorder(0, 8, 6, 8));
        wrapper.add(bar, BorderLayout.NORTH);
        wrapper.add(footer, BorderLayout.CENTER);
        return wrapper;
    }

    // ------------------------------------------------------------------ sidebar

    private JComponent buildSidebar() {
        filterField.putClientProperty("JTextField.placeholderText", "Find a tool  (" + shortcutName() + "K)");
        filterField.putClientProperty("JTextField.showClearButton", true);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { rebuildNav(); }
            public void removeUpdate(DocumentEvent e) { rebuildNav(); }
            public void changedUpdate(DocumentEvent e) { rebuildNav(); }
        });
        filterField.addActionListener(e -> {
            Optional<EasterEggs.Egg> egg = EasterEggs.match(filterField.getText());
            if (egg.isPresent()) {
                filterField.setText("");
                runEgg(egg.get());
                return;
            }
            firstEntry().ifPresent(x -> {
                showScreen(x.title());
                navList.requestFocusInWindow();
            });
        });
        filterField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clear");
        filterField.getActionMap().put("clear", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filterField.setText("");
                navList.requestFocusInWindow();
            }
        });
        filterField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "toList");
        filterField.getActionMap().put("toList", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                navList.requestFocusInWindow();
            }
        });

        navList.setSelectionModel(new DefaultListSelectionModel() {
            @Override
            public void setSelectionInterval(int anchor, int lead) {
                int prev = getLeadSelectionIndex();
                int dir = prev >= 0 && lead < prev ? -1 : 1;
                int i = lead;
                while (i >= 0 && i < navModel.size() && navModel.get(i) instanceof Header) {
                    i += dir;
                }
                if (i >= 0 && i < navModel.size()) {
                    super.setSelectionInterval(i, i);
                }
            }
        });
        navList.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        navList.setCellRenderer(new NavRenderer());
        navList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !syncingSelection && navList.getSelectedValue() instanceof Entry x) {
                showScreen(x.title());
            }
        });
        rebuildNav();

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(new EmptyBorder(8, 8, 6, 8));
        top.add(filterField, BorderLayout.CENTER);

        JScrollPane scroll = new JScrollPane(navList);
        scroll.setBorder(null);
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.add(top, BorderLayout.NORTH);
        sidebar.add(scroll, BorderLayout.CENTER);
        sidebar.setMinimumSize(new Dimension(160, 0));
        return sidebar;
    }

    private void rebuildNav() {
        List<Entry> matches = ScreenCatalog.filter(filterField.getText());
        syncingSelection = true;
        try {
            navModel.clear();
            for (String group : ScreenCatalog.GROUPS) {
                List<Entry> inGroup = matches.stream().filter(m -> m.group().equals(group)).toList();
                if (!inGroup.isEmpty()) {
                    navModel.addElement(new Header(group));
                    inGroup.forEach(navModel::addElement);
                }
            }
            if (current != null) {
                ScreenCatalog.byTitle(current).ifPresent(e -> {
                    int i = navModel.indexOf(e);
                    if (i >= 0) {
                        navList.setSelectedIndex(i);
                    }
                });
            }
        } finally {
            syncingSelection = false;
        }
    }

    private Optional<Entry> firstEntry() {
        for (int i = 0; i < navModel.size(); i++) {
            if (navModel.get(i) instanceof Entry e) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    private void selectInSidebar(Entry entry) {
        syncingSelection = true;
        try {
            int i = navModel.indexOf(entry);
            if (i < 0 && !filterField.getText().isEmpty()) {
                filterField.setText(""); // the screen was hidden by the filter; show everything again
                i = navModel.indexOf(entry);
            }
            if (i >= 0) {
                navList.setSelectedIndex(i);
                navList.ensureIndexIsVisible(i);
            }
        } finally {
            syncingSelection = false;
        }
    }

    private final class NavRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
            if (value instanceof Header h) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, h.name().toUpperCase(), index, false, false);
                l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize2D() - 1f));
                l.setForeground(UIManager.getColor("Label.disabledForeground"));
                l.setBorder(new EmptyBorder(index == 0 ? 4 : 12, 10, 3, 8));
                return l;
            }
            Entry e = (Entry) value;
            String text = e.label() + (poppedOut.containsKey(e.title()) ? "  ↗" : "");
            JLabel l = (JLabel) super.getListCellRendererComponent(list, text, index, selected, focus);
            l.setBorder(new EmptyBorder(4, 20, 4, 8));
            return l;
        }
    }

    // ------------------------------------------------------------------ content area

    private JComponent buildContentArea() {
        groupLabel.setFont(groupLabel.getFont().deriveFont(Font.BOLD, groupLabel.getFont().getSize2D() - 1f));
        groupLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, titleLabel.getFont().getSize2D() + 5f));
        popOutButton.setToolTipText("Show this screen in its own window, e.g. to use two tools side by side");
        popOutButton.addActionListener(e -> togglePopOut(current));

        JPanel titles = new JPanel(new GridLayout(2, 1));
        titles.setOpaque(false);
        titles.add(groupLabel);
        titles.add(titleLabel);
        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")),
                new EmptyBorder(8, 14, 8, 12)));
        header.add(titles, BorderLayout.CENTER);
        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 6));
        headerButtons.setOpaque(false);
        headerButtons.add(popOutButton);
        header.add(headerButtons, BorderLayout.EAST);

        JPanel area = new JPanel(new BorderLayout());
        area.add(header, BorderLayout.NORTH);
        area.add(cardPanel, BorderLayout.CENTER);
        area.add(footerHolder, BorderLayout.SOUTH);
        return area;
    }

    /** Moves a screen into its own window, or back into the main window if it's already out. */
    void togglePopOut(String title) {
        if (title == null) {
            return;
        }
        JFrame existing = poppedOut.get(title);
        if (existing != null) {
            existing.dispatchEvent(new WindowEvent(existing, WindowEvent.WINDOW_CLOSING));
            return;
        }
        JComponent content = contents.get(title);
        JPanel holder = holders.get(title);
        if (content == null || holder == null) {
            return;
        }
        holder.remove(content);
        holder.add(poppedOutNote(title), BorderLayout.CENTER);
        holder.revalidate();
        holder.repaint();

        Entry entry = ScreenCatalog.byTitle(title).orElseThrow();
        JFrame frame = new JFrame(entry.group() + " — " + entry.label() + " · Codes Switcher");
        frame.setIconImages(getIconImages());
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setContentPane(new JPanel(new BorderLayout()));
        frame.getContentPane().add(content, BorderLayout.CENTER);
        frame.setSize(Math.max(800, cardPanel.getWidth()), Math.max(600, cardPanel.getHeight() + 40));
        frame.setLocationByPlatform(true);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                bringBack(title, frame);
            }
        });
        poppedOut.put(title, frame);
        popOutButton.setText("Bring Back Here");
        navList.repaint();
        frame.setVisible(true);
    }

    private void bringBack(String title, JFrame frame) {
        JComponent content = contents.get(title);
        JPanel holder = holders.get(title);
        frame.getContentPane().remove(content);
        frame.dispose();
        poppedOut.remove(title);
        holder.removeAll();
        holder.add(content, BorderLayout.CENTER);
        holder.revalidate();
        holder.repaint();
        if (title.equals(current)) {
            popOutButton.setText("Open in New Window");
        }
        navList.repaint();
    }

    private JComponent poppedOutNote(String title) {
        JButton show = new JButton("Show Window");
        show.addActionListener(e -> {
            JFrame f = poppedOut.get(title);
            if (f != null) {
                f.toFront();
            }
        });
        JButton back = new JButton("Bring Back Here");
        back.addActionListener(e -> togglePopOut(title));
        JLabel note = new JLabel("This screen is open in its own window.");
        JPanel row = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 8));
        row.add(show);
        row.add(back);
        JPanel box = new JPanel(new GridBagLayout());
        JPanel inner = new JPanel(new BorderLayout(0, 6));
        note.setHorizontalAlignment(SwingConstants.CENTER);
        inner.add(note, BorderLayout.NORTH);
        inner.add(row, BorderLayout.CENTER);
        box.add(inner);
        return box;
    }

    // ------------------------------------------------------------------ menus and shortcuts

    private JMenuBar buildMenuBar() {
        int mod = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        JMenuBar bar = new JMenuBar();

        JMenu file = new JMenu("File");
        JMenuItem popOut = new JMenuItem("Open Screen in New Window");
        popOut.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_N, mod | KeyEvent.SHIFT_DOWN_MASK));
        popOut.addActionListener(e -> togglePopOut(current));
        file.add(popOut);
        JMenuItem clearHistory = new JMenuItem("Clear History");
        clearHistory.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Clear the session history?", "Clear History",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                SessionHistory.global().clear();
            }
        });
        file.add(clearHistory);
        file.addSeparator();
        JMenuItem exit = new JMenuItem("Exit");
        exit.addActionListener(e -> exit());
        file.add(exit);
        bar.add(file);

        JMenu go = new JMenu("Go");
        JMenuItem find = new JMenuItem("Find a Tool…");
        find.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_K, mod));
        find.addActionListener(e -> focusSearch());
        go.add(find);
        go.addSeparator();
        for (int i = 0; i < ScreenCatalog.GROUPS.size(); i++) {
            String group = ScreenCatalog.GROUPS.get(i);
            JMenuItem item = new JMenuItem(group);
            item.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_1 + i, mod));
            item.addActionListener(e -> showScreen(ScreenCatalog.inGroup(group).get(0).title()));
            go.add(item);
        }
        bar.add(go);

        bar.add(AppLauncher.createThemeMenu());

        JMenu help = new JMenu("Help");
        JMenuItem about = new JMenuItem("About");
        about.addActionListener(e -> new AboutDialog(this).setVisible(true));
        help.add(about);
        bar.add(help);
        return bar;
    }

    private void installShortcuts() {
        // Menu accelerators cover most keys; this one also works while a pop-out window has focus elsewhere.
        JRootPane root = getRootPane();
        int mod = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_F, mod | KeyEvent.SHIFT_DOWN_MASK), "find");
        root.getActionMap().put("find", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                focusSearch();
            }
        });
    }

    /** What each code word typed in the search does; see {@link EasterEggs}. */
    void runEgg(EasterEggs.Egg egg) {
        switch (egg) {
            case COURIER -> toggleCourierMode();
            case SETEC -> {
                boolean on = !EasterEggs.isOn(egg);
                EasterEggs.set(egg, on);
                if (on) {
                    SetecDialog.show(this);
                } else {
                    info("Back to boring, instant output.", "Setec Astronomy");
                }
            }
            case JOSHUA -> WoprDialog.open(this);
            case RABBIT -> {
                boolean on = !EasterEggs.isOn(egg);
                EasterEggs.set(egg, on);
                MatrixProgressBarUI.setEnabled(on);
                info(on ? "<html><b>Follow the white rabbit.</b><br><br>Progress bars now run on digital rain."
                        + "<br>Type \"white rabbit\" again to wake up.</html>"
                        : "Back to the real world. Progress bars are normal again.", "White Rabbit");
            }
            case PLANET -> {
                boolean on = !EasterEggs.isOn(egg);
                if (on && CourierMode.isOn()) {
                    CourierMode.set(false); // one hidden theme at a time
                }
                EasterEggs.set(egg, on);
                if (on) {
                    ThemeManager.applyPlanetTheme();
                } else {
                    restoreSavedTheme();
                }
                info(on ? "<html><b>HACK THE PLANET!</b><br><br>Type it again to go back to your theme.</html>"
                        : "Back to your usual theme.", "Hack the Planet");
            }
        }
    }

    private void restoreSavedTheme() {
        if (!ThemeManager.applyTheme(prefs.getTheme())) {
            ThemeManager.applyTheme("Flat Light");
        }
    }

    private void info(String text, String title) {
        if (!GraphicsEnvironment.isHeadless()) {
            JOptionPane.showMessageDialog(this, text, title, JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** The Courier Mode egg: see {@link CourierMode}. */
    void toggleCourierMode() {
        boolean on = !CourierMode.isOn();
        filterField.setText("");
        if (on) {
            EasterEggs.set(EasterEggs.Egg.PLANET, false); // one hidden theme at a time
            ThemeManager.applyCourierTheme();
        } else {
            restoreSavedTheme();
        }
        CourierMode.set(on);
        if (on) {
            showScreen(StegoPanels.HIDE);
        }
        if (!GraphicsEnvironment.isHeadless()) {
            JOptionPane.showMessageDialog(this, on
                    ? "<html><b>COURIER MODE ONLINE</b><br><br>"
                    + "Hide Message and Reveal Message can now use <b>three images</b> as the key instead of a password.<br>"
                    + "Anyone with the same three image files can reveal the message, so keep them as private as a password.<br><br>"
                    + "Type \"" + CourierMode.CODE_WORD + "\" in the search again to switch it off.</html>"
                    : "Courier Mode offline. Passwords only, and your theme is back.",
                    "Courier Mode", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    void focusSearch() {
        filterField.requestFocusInWindow();
        filterField.selectAll();
    }

    private static String shortcutName() {
        return System.getProperty("os.name", "").toLowerCase().contains("mac") ? "⌘" : "Ctrl+";
    }

    // ------------------------------------------------------------------ window state

    private void restoreBounds() {
        Rectangle saved = prefs.getWindowBounds();
        if (saved != null && onScreen(saved)) {
            setBounds(saved);
        } else {
            setSize(1100, 760);
            setLocationRelativeTo(null);
        }
        if (prefs.isMaximized()) {
            setExtendedState(getExtendedState() | MAXIMIZED_BOTH);
        }
    }

    /** True when a usable part of {@code r} is on some connected monitor (a monitor may have been unplugged). */
    private static boolean onScreen(Rectangle r) {
        if (GraphicsEnvironment.isHeadless()) {
            return false;
        }
        for (GraphicsDevice d : GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices()) {
            Rectangle visible = d.getDefaultConfiguration().getBounds().intersection(r);
            if (visible.width >= 200 && visible.height >= 150) {
                return true;
            }
        }
        return false;
    }

    void saveState() {
        boolean maximized = (getExtendedState() & MAXIMIZED_BOTH) == MAXIMIZED_BOTH;
        prefs.setMaximized(maximized);
        if (!maximized) {
            prefs.setWindowBounds(getBounds());
        }
        prefs.setSidebarWidth(split.getDividerLocation());
        if (current != null) {
            prefs.setLastScreen(current);
        }
    }

    private void exit() {
        saveState();
        dispose();
        System.exit(0);
    }

    /**
     * Silent unless there's something to say: no UI if up to date or the check fails, and only
     * once per newly released version. Runs in the background so it never delays startup.
     */
    private void checkForUpdateAndNotifyIfNewer() {
        new SwingWorker<Optional<UpdateChecker.ReleaseInfo>, Void>() {
            @Override
            protected Optional<UpdateChecker.ReleaseInfo> doInBackground() {
                return UpdateChecker.fetchLatestRelease();
            }

            @Override
            protected void done() {
                try {
                    Optional<UpdateChecker.ReleaseInfo> release = get();
                    if (release.isEmpty() || !UpdateChecker.isNewerVersion(release.get().version(), AppVersion.get())
                            || release.get().version().equals(prefs.getLastNotifiedUpdateVersion())) {
                        return;
                    }
                    prefs.setLastNotifiedUpdateVersion(release.get().version());
                    new AboutDialog(MainWindow.this, release.get()).setVisible(true);
                } catch (Exception e) {
                    log.warn("Silent startup update check failed", e);
                }
            }
        }.execute();
    }
}
