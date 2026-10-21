package com.ourgiant.crypt;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Code words typed in the sidebar search that switch on hidden extras, each a nod to a film.
 * Toggles last for this session only. Courier Mode keeps its own state in {@link CourierMode}.
 */
final class EasterEggs {

    enum Egg {
        /** Johnny Mnemonic: three-image keys. */
        COURIER("mnemonic", "johnny mnemonic"),
        /** Sneakers: decrypted output unscrambles letter by letter. */
        SETEC("setec astronomy", "too many secrets"),
        /** WarGames: the password strength checker. Opens a window; nothing to toggle. */
        JOSHUA("joshua", "shall we play a game"),
        /** The Matrix: digital-rain progress bars. */
        RABBIT("white rabbit", "follow the white rabbit"),
        /** Hackers: a loud neon theme. */
        PLANET("hack the planet"),
        /** Severance: sort the scary numbers. Opens a window; nothing to toggle. */
        MDR("macrodata refinement", "macrodata", "mdr", "lumon");

        private final List<String> words;

        Egg(String... words) {
            this.words = List.of(words);
        }

        List<String> words() {
            return words;
        }
    }

    private static final Set<Egg> on = ConcurrentHashMap.newKeySet();
    private static final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private static final Map<String, Egg> byWord = new ConcurrentHashMap<>();

    static {
        for (Egg e : Egg.values()) {
            e.words().forEach(w -> byWord.put(norm(w), e));
        }
    }

    private EasterEggs() {
    }

    /** The egg a typed search matches, ignoring case, spaces and punctuation. */
    static Optional<Egg> match(String typed) {
        return typed == null ? Optional.empty() : Optional.ofNullable(byWord.get(norm(typed)));
    }

    static boolean isOn(Egg egg) {
        return egg == Egg.COURIER ? CourierMode.isOn() : on.contains(egg);
    }

    static void set(Egg egg, boolean value) {
        if (egg == Egg.COURIER) {
            CourierMode.set(value);
            return;
        }
        boolean changed = value ? on.add(egg) : on.remove(egg);
        if (changed) {
            listeners.forEach(Runnable::run);
        }
    }

    static void addListener(Runnable r) {
        listeners.add(r);
    }

    private static String norm(String s) {
        return s.toLowerCase(Locale.ROOT).replaceAll("[^a-z]", "");
    }
}
