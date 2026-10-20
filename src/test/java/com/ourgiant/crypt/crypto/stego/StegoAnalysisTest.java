package com.ourgiant.crypt.crypto.stego;

import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class StegoAnalysisTest {

    @Test
    void gammaFunctionMatchesClosedForms() {
        for (double x : new double[]{0.1, 0.5, 1, 2, 5, 10}) {
            assertEquals(1 - Math.exp(-x), StegoAnalysis.regularizedGammaP(1, x), 1e-10, "P(1,x)");
            // P(2, x) = 1 - e^-x (1 + x)
            assertEquals(1 - Math.exp(-x) * (1 + x), StegoAnalysis.regularizedGammaP(2, x), 1e-10, "P(2,x)");
        }
        assertEquals(Math.log(24), StegoAnalysis.lnGamma(5), 1e-9);
    }

    /** A smooth image using only even values: pairs are maximally unequal, as in many real images. */
    private static BufferedImage evenOnly(int w, int h) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int v = ((x + y) % 128) * 2;
                img.setRGB(x, y, (v << 16) | (v << 8) | v);
            }
        }
        return img;
    }

    @Test
    void cleanImageScoresLowAndFullSequentialEmbeddingScoresHigh() {
        BufferedImage clean = evenOnly(200, 200);
        assertTrue(StegoAnalysis.analyze(clean).maxProbability() < 0.05);

        BufferedImage filled = evenOnly(200, 200);
        Random r = new Random(3);
        for (int y = 0; y < 200; y++) {
            for (int x = 0; x < 200; x++) {
                filled.setRGB(x, y, filled.getRGB(x, y) ^ (r.nextInt(8) & 0x010101) ^ (r.nextBoolean() ? 0x010000 : 0)
                        ^ (r.nextBoolean() ? 0x000100 : 0) ^ (r.nextBoolean() ? 1 : 0));
            }
        }
        StegoAnalysis.Report rep = StegoAnalysis.analyze(filled);
        assertTrue(rep.red().embeddingProbability() > 0.95, "red " + rep.red());
        assertTrue(rep.blue().embeddingProbability() > 0.95, "blue " + rep.blue());
        assertEquals(0.5, rep.green().onesRatio(), 0.02);
    }

    @Test
    void lsbPlaneShowsOnlyLowBits() {
        BufferedImage img = new BufferedImage(2, 1, BufferedImage.TYPE_INT_RGB);
        img.setRGB(0, 0, 0x010203);
        img.setRGB(1, 0, 0xfefefe);
        BufferedImage plane = StegoAnalysis.lsbPlane(img);
        assertEquals(0xffff00ff, plane.getRGB(0, 0)); // R=1, G=0, B=1
        assertEquals(0xff000000, plane.getRGB(1, 0));
    }
}
