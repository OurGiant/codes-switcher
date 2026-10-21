package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class MacrodataFileTest {

    private static MacrodataFile file(long seed) {
        return new MacrodataFile(MacrodataDialog.COLS, MacrodataDialog.ROWS, MacrodataDialog.CLUSTERS, new Random(seed));
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 2, 3, 42, 1234, 99999})
    void clustersFitWithAGapAndDontOverlap(long seed) {
        MacrodataFile f = file(seed);
        List<MacrodataFile.Cluster> ks = f.clusters();
        assertEquals(MacrodataDialog.CLUSTERS, ks.size(), "all clusters placed");
        Set<String> seen = new HashSet<>();
        for (MacrodataFile.Cluster k : ks) {
            assertTrue(k.cells.size() >= 4 && k.cells.size() <= 9);
            for (int[] cell : k.cells) {
                assertTrue(seen.add(cell[0] + "," + cell[1]), "cell used twice");
                assertSame(k, f.clusterAt(cell[0], cell[1]).orElseThrow());
                // No neighbouring cell belongs to a different cluster.
                for (int dc = -1; dc <= 1; dc++) {
                    for (int dr = -1; dr <= 1; dr++) {
                        f.clusterAt(cell[0] + dc, cell[1] + dr).ifPresent(o -> assertSame(k, o));
                    }
                }
            }
        }
        assertTrue(f.clusterAt(-1, 0).isEmpty());
        assertTrue(f.clusterAt(MacrodataDialog.COLS, 0).isEmpty());
    }

    @Test
    void refiningFillsBinsAndCompletesTheFile() {
        MacrodataFile f = file(7);
        assertEquals(0, f.percentComplete());
        assertFalse(f.isComplete());
        List<MacrodataFile.Cluster> ks = f.clusters();
        for (int i = 0; i < ks.size(); i++) {
            MacrodataFile.Cluster k = ks.get(i);
            int before = f.percentComplete();
            assertTrue(f.refine(k, i % MacrodataFile.BINS));
            assertFalse(f.refine(k, 0), "can't refine twice");
            assertTrue(f.percentComplete() > before || f.percentComplete() == 100);
            int[] cell = k.cells.get(0);
            assertTrue(f.isRefined(cell[0], cell[1]));
            assertTrue(f.clusterAt(cell[0], cell[1]).isEmpty(), "refined numbers can't be selected again");
            assertTrue(f.fill(i % MacrodataFile.BINS, k.temper) > 0);
        }
        assertEquals(100, f.percentComplete());
        assertTrue(f.isComplete());
        for (int b = 0; b < MacrodataFile.BINS; b++) {
            for (int t = 0; t < MacrodataFile.TEMPERS.length; t++) {
                assertTrue(f.fill(b, t) >= 0 && f.fill(b, t) <= 1);
            }
        }
    }

    @Test
    void sameSeedSameFile() {
        MacrodataFile a = file(5);
        MacrodataFile b = file(5);
        assertEquals(a.name, b.name);
        for (int c = 0; c < a.cols; c++) {
            for (int r = 0; r < a.rows; r++) {
                assertEquals(a.digit(c, r), b.digit(c, r));
            }
        }
    }

    @Test
    void rejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> new MacrodataFile(2, 2, 3, new Random()));
        MacrodataFile f = file(1);
        assertThrows(IllegalArgumentException.class, () -> f.refine(f.clusters().get(0), MacrodataFile.BINS));
    }
}
