package com.ourgiant.crypt;

/** The "Copy as…" formats offered on text boxes. Swing-free so the escaping can be unit-tested. */
public enum CopyFormat {
    RAW("Plain Text"),
    JSON("JSON / JavaScript String"),
    JAVA("Java String"),
    PYTHON("Python String"),
    MARKDOWN("Markdown Code Block");

    private final String label;

    CopyFormat(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public String format(String text) {
        return switch (this) {
            case RAW -> text;
            case JSON -> '"' + escape(text, false) + '"';
            case JAVA -> '"' + escape(text, false) + '"';
            case PYTHON -> '"' + escape(text, true) + '"';
            case MARKDOWN -> markdown(text);
        };
    }

    /**
     * Escapes for a double-quoted string literal: backslash, quote, control characters, and the
     * Unicode line/paragraph separators (which break JavaScript string literals). Non-ASCII text
     * is kept as-is, since all three languages accept UTF-8 source.
     */
    private static String escape(String s, boolean python) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20 || c == 0x7f || c == '\u2028' || c == '\u2029') {
                        out.append(python && c < 0x100 ? String.format("\\x%02x", (int) c) : String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /** A fenced block whose fence is longer than any run of backticks inside the text. */
    private static String markdown(String text) {
        int longest = 0;
        int run = 0;
        for (int i = 0; i < text.length(); i++) {
            run = text.charAt(i) == '`' ? run + 1 : 0;
            longest = Math.max(longest, run);
        }
        String fence = "`".repeat(Math.max(3, longest + 1));
        return fence + "\n" + text + (text.endsWith("\n") ? "" : "\n") + fence + "\n";
    }
}
