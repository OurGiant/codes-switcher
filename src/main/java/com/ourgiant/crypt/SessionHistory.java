package com.ourgiant.crypt;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Recent operations, kept in memory only: nothing is ever written to disk and the list is gone
 * when the app closes. Tools record their input and output after a successful operation;
 * passwords and keys are never passed in. Swing-free so the rules can be unit-tested.
 */
public final class SessionHistory {

    /** Most entries kept; older ones drop off. */
    public static final int MAX_ENTRIES = 50;
    /** Longest input or output stored per entry, in characters. Longer values are cut. */
    public static final int MAX_CHARS = 256 * 1024;

    /**
     * One recorded operation. {@code restore} puts the input back into the tool, or is null when
     * that isn't possible (e.g. the value was cut to fit).
     */
    public record Entry(long id, Instant time, String screen, String operation,
                        String input, String output, boolean truncated, Runnable restore) {
        public boolean canRestore() {
            return restore != null;
        }
    }

    private static final SessionHistory GLOBAL = new SessionHistory();

    private final Deque<Entry> entries = new ArrayDeque<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final AtomicLong ids = new AtomicLong();

    /** The app-wide history the tools record into. */
    public static SessionHistory global() {
        return GLOBAL;
    }

    /**
     * Records an operation. Never pass passwords, secrets or private keys in {@code input} or
     * {@code output}, and don't capture them in {@code restore}.
     */
    public synchronized Entry record(String screen, String operation, String input, String output, Runnable restore) {
        String in = input == null ? "" : input;
        String out = output == null ? "" : output;
        boolean cut = in.length() > MAX_CHARS || out.length() > MAX_CHARS;
        Entry e = new Entry(ids.incrementAndGet(), Instant.now(), screen, operation,
                cut(in), cut(out), cut, cut ? null : restore);
        entries.addFirst(e);
        while (entries.size() > MAX_ENTRIES) {
            entries.removeLast();
        }
        fire();
        return e;
    }

    /** Newest first. */
    public synchronized List<Entry> entries() {
        return new ArrayList<>(entries);
    }

    public synchronized void clear() {
        entries.clear();
        fire();
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    private void fire() {
        listeners.forEach(Runnable::run);
    }

    private static String cut(String s) {
        return s.length() > MAX_CHARS ? s.substring(0, MAX_CHARS) + "\n… (cut to " + (MAX_CHARS / 1024) + " KB)" : s;
    }

    /** One-line preview for tables. */
    public static String preview(String s, int max) {
        String flat = s.replaceAll("\\s+", " ").strip();
        return flat.length() > max ? flat.substring(0, max - 1) + "…" : flat;
    }
}
