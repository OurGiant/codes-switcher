package com.ourgiant.crypt.crypto.stego;

import java.awt.image.BufferedImage;

/**
 * Simple steganalysis: the least-significant-bit plane, per-channel bit balance, and the
 * Westfeld–Pfitzmann chi-square test for LSB replacement.
 *
 * The chi-square test is strong against data written sequentially across most of the image and
 * weak against small, scattered payloads (like this app's own output), so a low score means
 * "no obvious sign", not "nothing hidden".
 */
public final class StegoAnalysis {

    public record ChannelStats(String channel, double onesRatio, double embeddingProbability) {
    }

    public record Report(int width, int height, ChannelStats red, ChannelStats green, ChannelStats blue,
                         double topRegionProbability) {
        /** Highest embedding probability over the channels and the top-of-image region. */
        public double maxProbability() {
            return Math.max(topRegionProbability,
                    Math.max(red.embeddingProbability(), Math.max(green.embeddingProbability(), blue.embeddingProbability())));
        }
    }

    private StegoAnalysis() {
    }

    /** Each colour channel becomes 0 or 255 depending on its lowest bit, so hidden patterns become visible. */
    public static BufferedImage lsbPlane(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        int[] px = img.getRGB(0, 0, w, h, null, 0, w);
        for (int i = 0; i < px.length; i++) {
            int p = px[i];
            int r = ((p >> 16) & 1) * 255;
            int g = ((p >> 8) & 1) * 255;
            int b = (p & 1) * 255;
            px[i] = 0xff000000 | (r << 16) | (g << 8) | b;
        }
        BufferedImage out = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        out.setRGB(0, 0, w, h, px, 0, w);
        return out;
    }

    public static Report analyze(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        int[] px = img.getRGB(0, 0, w, h, null, 0, w);
        ChannelStats r = channel("Red", px, 16, px.length);
        ChannelStats g = channel("Green", px, 8, px.length);
        ChannelStats b = channel("Blue", px, 0, px.length);
        // Sequential embedders fill from the top: test the first 10% of rows on all channels together.
        int top = Math.max(1, h / 10) * w;
        double topP = Math.max(channel("", px, 16, top).embeddingProbability(),
                Math.max(channel("", px, 8, top).embeddingProbability(), channel("", px, 0, top).embeddingProbability()));
        return new Report(w, h, r, g, b, topP);
    }

    private static ChannelStats channel(String name, int[] px, int shift, int count) {
        long[] hist = new long[256];
        long ones = 0;
        for (int i = 0; i < count; i++) {
            int v = (px[i] >> shift) & 0xff;
            hist[v]++;
            ones += v & 1;
        }
        return new ChannelStats(name, count == 0 ? 0 : (double) ones / count, chiSquareEmbedding(hist));
    }

    /**
     * Westfeld–Pfitzmann: LSB replacement equalises the counts of each value pair (2k, 2k+1).
     * Returns the probability that the histogram came from embedding (close to 1 = suspicious).
     */
    static double chiSquareEmbedding(long[] hist) {
        double chi = 0;
        int dof = -1;
        for (int k = 0; k < 128; k++) {
            double expected = (hist[2 * k] + hist[2 * k + 1]) / 2.0;
            if (expected > 4) {
                double d = hist[2 * k] - expected;
                chi += d * d / expected;
                dof++;
            }
        }
        if (dof < 1) {
            return 0;
        }
        return 1 - regularizedGammaP(dof / 2.0, chi / 2.0);
    }

    // ---- regularised lower incomplete gamma P(a, x) (series / continued fraction) ----

    static double regularizedGammaP(double a, double x) {
        if (x <= 0) {
            return 0;
        }
        if (x < a + 1) {
            double sum = 1 / a;
            double term = sum;
            for (int n = 1; n < 1000; n++) {
                term *= x / (a + n);
                sum += term;
                if (Math.abs(term) < Math.abs(sum) * 1e-15) {
                    break;
                }
            }
            return Math.min(1, sum * Math.exp(-x + a * Math.log(x) - lnGamma(a)));
        }
        // Lentz's continued fraction for Q, then P = 1 - Q
        double b = x + 1 - a;
        double c = 1 / 1e-300;
        double d = 1 / b;
        double f = d;
        for (int i = 1; i < 1000; i++) {
            double an = -i * (i - a);
            b += 2;
            d = an * d + b;
            if (Math.abs(d) < 1e-300) {
                d = 1e-300;
            }
            c = b + an / c;
            if (Math.abs(c) < 1e-300) {
                c = 1e-300;
            }
            d = 1 / d;
            double delta = d * c;
            f *= delta;
            if (Math.abs(delta - 1) < 1e-15) {
                break;
            }
        }
        double q = Math.exp(-x + a * Math.log(x) - lnGamma(a)) * f;
        return Math.max(0, 1 - q);
    }

    /** Lanczos approximation of ln Γ(x). */
    static double lnGamma(double x) {
        double[] g = {76.18009172947146, -86.50532032941677, 24.01409824083091,
                -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5};
        double y = x;
        double tmp = x + 5.5;
        tmp -= (x + 0.5) * Math.log(tmp);
        double ser = 1.000000000190015;
        for (double c : g) {
            ser += c / ++y;
        }
        return -tmp + Math.log(2.5066282746310005 * ser / x);
    }
}
