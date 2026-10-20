package com.ourgiant.crypt;

import java.util.ArrayList;
import java.util.List;

/**
 * An ordered list of Text Codecs steps run one after another, each on the previous step's output.
 * A recipe can be written as text, one step per line: {@code decode URL}, {@code encode Base64}, ...
 */
public final class Recipe {

    public enum Direction {
        ENCODE, DECODE;

        String word() {
            return name().toLowerCase();
        }
    }

    public record Step(Direction direction, String method) {
        public Step {
            if (!TextCodec.METHODS.contains(method)) {
                throw new IllegalArgumentException("Unknown method: " + method);
            }
            if (direction == Direction.DECODE && TextCodec.isHash(method)) {
                throw new IllegalArgumentException(method + " is a one-way hash and can't be decoded");
            }
            if (direction == Direction.ENCODE && TextCodec.isDecodeOnly(method)) {
                throw new IllegalArgumentException(method + " can only decode");
            }
        }

        @Override
        public String toString() {
            return direction.word() + " " + method;
        }
    }

    /** Result of one step: its output, or the error that stopped the recipe. */
    public record StepResult(Step step, String output, String error) {
        public boolean ok() {
            return error == null;
        }
    }

    private final List<Step> steps;

    public Recipe(List<Step> steps) {
        this.steps = List.copyOf(steps);
    }

    public List<Step> steps() {
        return steps;
    }

    /** Runs every step in order and stops at the first one that fails. */
    public List<StepResult> run(String input) {
        List<StepResult> results = new ArrayList<>();
        String current = input;
        for (Step step : steps) {
            try {
                current = step.direction() == Direction.ENCODE
                        ? TextCodec.encode(current, step.method())
                        : TextCodec.decode(current, step.method());
                results.add(new StepResult(step, current, null));
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                results.add(new StepResult(step, null, msg));
                break;
            }
        }
        return results;
    }

    /** One step per line, e.g. "decode URL". */
    public String toText() {
        StringBuilder sb = new StringBuilder();
        for (Step s : steps) {
            sb.append(s).append('\n');
        }
        return sb.toString();
    }

    /** Parses {@link #toText()} output. Blank lines and lines starting with # are ignored. */
    public static Recipe parse(String text) {
        List<Step> steps = new ArrayList<>();
        String[] lines = text.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            int lineNo = i + 1;
            String line = lines[i].strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int space = line.indexOf(' ');
            if (space < 0) {
                throw new IllegalArgumentException("Line " + (i + 1) + ": expected \"encode <method>\" or \"decode <method>\"");
            }
            String dir = line.substring(0, space).toLowerCase();
            String method = line.substring(space + 1).strip();
            Direction direction = switch (dir) {
                case "encode" -> Direction.ENCODE;
                case "decode" -> Direction.DECODE;
                default -> throw new IllegalArgumentException("Line " + (i + 1) + ": \"" + dir
                        + "\" should be encode or decode");
            };
            String known = TextCodec.METHODS.stream().filter(m -> m.equalsIgnoreCase(method)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Line " + lineNo + ": unknown method \"" + method + "\""));
            try {
                steps.add(new Step(direction, known));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Line " + (i + 1) + ": " + e.getMessage());
            }
        }
        return new Recipe(steps);
    }
}
