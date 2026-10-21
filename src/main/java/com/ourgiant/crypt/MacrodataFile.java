package com.ourgiant.crypt;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

/**
 * The model behind the Macrodata Refinement egg (a nod to <i>Severance</i>): a grid of digits
 * with hidden "scary" clusters to sort into five bins, each with four temper bars. Swing-free so it
 * can be tested; {@link MacrodataDialog} draws it.
 */
final class MacrodataFile {

    static final String[] TEMPERS = {"WO", "FC", "DR", "MA"};
    static final int BINS = 5;
    static final String[] NAMES = {"Cold Harbor", "Siena", "Allentown", "Tumwater", "Dranesville"};

    /** A group of scary numbers. {@code temper} is an index into {@link #TEMPERS}. */
    static final class Cluster {
        final int id;
        final List<int[]> cells;
        final int temper;
        private int bin = -1;

        Cluster(int id, List<int[]> cells, int temper) {
            this.id = id;
            this.cells = List.copyOf(cells);
            this.temper = temper;
        }

        boolean refined() {
            return bin >= 0;
        }

        int bin() {
            return bin;
        }
    }

    final String name;
    final int cols;
    final int rows;
    private final int[][] digits;
    private final int[][] owner; // cluster id per cell, -1 for none
    private final List<Cluster> clusters = new ArrayList<>();
    private final int[][] binCells = new int[BINS][TEMPERS.length];
    private final int[] temperTotals = new int[TEMPERS.length];

    MacrodataFile(int cols, int rows, int clusterCount, Random random) {
        if (cols < 8 || rows < 6 || clusterCount < 1) {
            throw new IllegalArgumentException("grid too small");
        }
        this.name = NAMES[random.nextInt(NAMES.length)];
        this.cols = cols;
        this.rows = rows;
        this.digits = new int[cols][rows];
        this.owner = new int[cols][rows];
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                digits[c][r] = random.nextInt(10);
                owner[c][r] = -1;
            }
        }
        int attempts = 0;
        while (clusters.size() < clusterCount && attempts++ < clusterCount * 200) {
            List<int[]> cells = grow(random, 4 + random.nextInt(6));
            if (cells != null) {
                Cluster k = new Cluster(clusters.size(), cells, random.nextInt(TEMPERS.length));
                for (int[] cell : cells) {
                    owner[cell[0]][cell[1]] = k.id;
                }
                temperTotals[k.temper] += cells.size();
                clusters.add(k);
            }
        }
    }

    /** A blob of free cells grown by a random walk, keeping a one-cell gap from other clusters; null if it doesn't fit. */
    private List<int[]> grow(Random random, int size) {
        List<int[]> cells = new ArrayList<>();
        boolean[][] taken = new boolean[cols][rows];
        int c = 1 + random.nextInt(cols - 2);
        int r = 1 + random.nextInt(rows - 2);
        for (int tries = 0; cells.size() < size && tries < size * 20; tries++) {
            if (!taken[c][r] && free(c, r)) {
                taken[c][r] = true;
                cells.add(new int[]{c, r});
            }
            if (cells.isEmpty()) {
                return null;
            }
            int[] from = cells.get(random.nextInt(cells.size()));
            int dir = random.nextInt(4);
            c = Math.max(0, Math.min(cols - 1, from[0] + (dir == 0 ? 1 : dir == 1 ? -1 : 0)));
            r = Math.max(0, Math.min(rows - 1, from[1] + (dir == 2 ? 1 : dir == 3 ? -1 : 0)));
        }
        return cells.size() == size ? cells : null;
    }

    /** No cluster on this cell or its neighbours. */
    private boolean free(int c, int r) {
        for (int dc = -1; dc <= 1; dc++) {
            for (int dr = -1; dr <= 1; dr++) {
                int x = c + dc;
                int y = r + dr;
                if (x >= 0 && y >= 0 && x < cols && y < rows && owner[x][y] >= 0) {
                    return false;
                }
            }
        }
        return true;
    }

    int digit(int c, int r) {
        return digits[c][r];
    }

    List<Cluster> clusters() {
        return List.copyOf(clusters);
    }

    /** The unrefined cluster on this cell, if any. */
    Optional<Cluster> clusterAt(int c, int r) {
        if (c < 0 || r < 0 || c >= cols || r >= rows || owner[c][r] < 0) {
            return Optional.empty();
        }
        Cluster k = clusters.get(owner[c][r]);
        return k.refined() ? Optional.empty() : Optional.of(k);
    }

    boolean isRefined(int c, int r) {
        return owner[c][r] >= 0 && clusters.get(owner[c][r]).refined();
    }

    /** Sorts a cluster into a bin. False if it was already refined. */
    boolean refine(Cluster k, int bin) {
        if (bin < 0 || bin >= BINS) {
            throw new IllegalArgumentException("bin " + bin);
        }
        if (k.refined()) {
            return false;
        }
        k.bin = bin;
        binCells[bin][k.temper] += k.cells.size();
        return true;
    }

    /** How full a bin's temper bar is, 0 to 1: each bin's share is a fifth of that temper's numbers. */
    double fill(int bin, int temper) {
        double share = Math.max(1.0, temperTotals[temper] / (double) BINS);
        return Math.min(1.0, binCells[bin][temper] / share);
    }

    /** Percent of scary numbers refined, 0 to 100. */
    int percentComplete() {
        int total = 0;
        int done = 0;
        for (Cluster k : clusters) {
            total += k.cells.size();
            if (k.refined()) {
                done += k.cells.size();
            }
        }
        return total == 0 ? 100 : (int) Math.floor(100.0 * done / total);
    }

    boolean isComplete() {
        return clusters.stream().allMatch(Cluster::refined);
    }
}
