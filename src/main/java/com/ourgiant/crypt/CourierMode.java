package com.ourgiant.crypt;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Easter egg, a nod to <i>Johnny Mnemonic</i> (1995): type the code word in the sidebar search to
 * let Hide/Reveal Message use three images as the key, in a neon theme. Lasts for this session only.
 */
final class CourierMode {

    static final String CODE_WORD = "mnemonic";

    private static volatile boolean on;
    private static final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    private CourierMode() {
    }

    static boolean isOn() {
        return on;
    }

    /** True for what the user types to toggle the mode: the code word, ignoring case, spaces and punctuation. */
    static boolean isCodeWord(String typed) {
        return EasterEggs.match(typed).filter(e -> e == EasterEggs.Egg.COURIER).isPresent();
    }

    static void set(boolean value) {
        if (on == value) {
            return;
        }
        on = value;
        listeners.forEach(Runnable::run);
    }

    /** Called on every change; the panels use it to show or hide their three-image options. */
    static void addListener(Runnable r) {
        listeners.add(r);
    }
}
