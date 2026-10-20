package com.ourgiant.crypt.crypto.stego;

import com.ourgiant.crypt.crypto.PasswordCipher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.awt.image.IndexColorModel;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.BitSet;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SteganographyTest {

    // Light key derivation keeps the suite fast; the production defaults are much higher.
    private final Steganography stego = new Steganography(new PasswordCipher(1_000), 1_000);
    private static final char[] PW = "correct horse battery".toCharArray();

    static BufferedImage photoLike(int w, int h, int type) {
        BufferedImage img = new BufferedImage(w, h, type);
        Random r = new Random(1);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int red = (x * 255 / w + r.nextInt(7)) & 0xff;
                int green = (y * 255 / h + r.nextInt(7)) & 0xff;
                int blue = ((x + y) * 128 / (w + h) + r.nextInt(7)) & 0xff;
                int alpha = type == BufferedImage.TYPE_INT_ARGB ? 128 + (x % 128) : 255;
                img.setRGB(x, y, (alpha << 24) | (red << 16) | (green << 8) | blue);
            }
        }
        return img;
    }

    static BufferedImage viaPng(BufferedImage img) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertTrue(ImageIO.write(img, "png", out));
        return ImageIO.read(new ByteArrayInputStream(out.toByteArray()));
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 2, 3, 7, 64, 255, 256, 257, 300, 3 * 17 * 13})
    void placementIsABijection(long n) {
        Steganography.Placement p = new Steganography.Placement(n, new long[]{11, 22, 33, 44});
        BitSet seen = new BitSet();
        for (long i = 0; i < n; i++) {
            long s = p.slot(i);
            assertTrue(s >= 0 && s < n);
            assertFalse(seen.get((int) s), "slot used twice");
            seen.set((int) s);
        }
        assertEquals(n, seen.cardinality());
    }

    @Test
    void placementScattersAcrossTheImage() {
        Steganography.Placement p = new Steganography.Placement(3L * 1000 * 1000, new long[]{1, 2, 3, 4});
        long low = 0;
        for (int i = 0; i < 1000; i++) {
            if (p.slot(i) < 300_000) {
                low++; // first 10% of the image
            }
        }
        assertTrue(low > 50 && low < 150, "about 10% of early bits land in the first 10% of the image: " + low);
    }

    @Test
    void textRoundTripThroughPng() throws Exception {
        BufferedImage cover = photoLike(120, 80, BufferedImage.TYPE_INT_RGB);
        String msg = "Meet at the usual place 🔐\nline two";
        BufferedImage stegged = viaPng(stego.hide(cover, Steganography.Payload.text(msg), PW));
        Steganography.Payload back = stego.reveal(stegged, PW);
        assertTrue(back.isText());
        assertEquals(msg, back.text());
    }

    @Test
    void fileRoundTripKeepsNameAndBytes() throws Exception {
        BufferedImage cover = photoLike(200, 150, BufferedImage.TYPE_INT_RGB);
        byte[] data = new byte[5000];
        new Random(9).nextBytes(data);
        BufferedImage stegged = viaPng(stego.hide(cover, Steganography.Payload.file("report.pdf", data), PW));
        Steganography.Payload back = stego.reveal(stegged, PW);
        assertFalse(back.isText());
        assertEquals("report.pdf", back.fileName());
        assertArrayEquals(data, back.data());
    }

    @Test
    void alphaIsPreservedAndOnlyLowBitsChange() throws Exception {
        BufferedImage cover = photoLike(90, 60, BufferedImage.TYPE_INT_ARGB);
        BufferedImage out = stego.hide(cover, Steganography.Payload.text("x".repeat(400)), PW);
        int changed = 0;
        for (int y = 0; y < 60; y++) {
            for (int x = 0; x < 90; x++) {
                int a = cover.getRGB(x, y);
                int b = out.getRGB(x, y);
                assertEquals(a >>> 24, b >>> 24, "alpha untouched");
                assertEquals(0, (a ^ b) & 0x00fefefe, "only the lowest bit of each colour may differ");
                if (a != b) {
                    changed++;
                }
            }
        }
        assertTrue(changed > 0);
        assertEquals("x".repeat(400), stego.reveal(viaPng(out), PW).text());
    }

    @Test
    void paletteImageCoverWorks() throws Exception {
        byte[] r = new byte[256], g = new byte[256], b = new byte[256];
        for (int i = 0; i < 256; i++) {
            r[i] = (byte) i;
            g[i] = (byte) (255 - i);
            b[i] = (byte) (i / 2);
        }
        BufferedImage indexed = new BufferedImage(64, 64, BufferedImage.TYPE_BYTE_INDEXED, new IndexColorModel(8, 256, r, g, b));
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                indexed.getRaster().setSample(x, y, 0, (x * 4) & 0xff);
            }
        }
        BufferedImage out = viaPng(stego.hide(indexed, Steganography.Payload.text("palette ok"), PW));
        assertEquals("palette ok", stego.reveal(out, PW).text());
    }

    @Test
    void wrongPasswordAndCleanImageFindNothing() throws Exception {
        BufferedImage cover = photoLike(100, 100, BufferedImage.TYPE_INT_RGB);
        BufferedImage stegged = stego.hide(cover, Steganography.Payload.text("secret"), PW);
        assertThrows(Steganography.NotFoundException.class, () -> stego.reveal(stegged, "wrong".toCharArray()));
        assertThrows(Steganography.NotFoundException.class, () -> stego.reveal(cover, PW));
        assertThrows(Steganography.NotFoundException.class, () -> stego.reveal(photoLike(4, 4, BufferedImage.TYPE_INT_RGB), PW));
    }

    @Test
    void flippedHiddenBitIsReportedAsDamaged() throws Exception {
        BufferedImage stegged = stego.hide(photoLike(100, 100, BufferedImage.TYPE_INT_RGB),
                Steganography.Payload.text("integrity matters"), PW);
        // Flip one bit inside the ciphertext (after the 8-byte frame header).
        java.lang.reflect.Method key = Steganography.class.getDeclaredMethod("placementKey", char[].class);
        key.setAccessible(true);
        Steganography.Placement place = new Steganography.Placement(100L * 100 * 3, (long[]) key.invoke(stego, (Object) PW));
        long slot = place.slot(8 * 8 + 40);
        int px = (int) (slot / 3);
        int shift = 16 - 8 * (int) (slot % 3);
        stegged.setRGB(px % 100, px / 100, stegged.getRGB(px % 100, px / 100) ^ (1 << shift));
        assertThrows(Steganography.DamagedException.class, () -> stego.reveal(stegged, PW));
    }

    @Test
    void jpegRecompressionDestroysTheMessage() throws Exception {
        BufferedImage stegged = stego.hide(photoLike(160, 120, BufferedImage.TYPE_INT_RGB),
                Steganography.Payload.text("won't survive"), PW);
        ByteArrayOutputStream jpg = new ByteArrayOutputStream();
        ImageIO.write(stegged, "jpg", jpg);
        BufferedImage back = ImageIO.read(new ByteArrayInputStream(jpg.toByteArray()));
        Exception e = assertThrows(Exception.class, () -> stego.reveal(back, PW));
        assertTrue(e instanceof Steganography.NotFoundException || e instanceof Steganography.DamagedException, e.toString());
    }

    @Test
    void capacityIsEnforcedExactly() throws Exception {
        BufferedImage cover = photoLike(40, 40, BufferedImage.TYPE_INT_RGB);
        long cap = Steganography.capacityBytes(40, 40, null);
        assertTrue(cap > 400 && cap < 600, "40x40 holds about 0.5 KB: " + cap);
        String fits = "a".repeat((int) cap);
        assertEquals(fits, stego.reveal(stego.hide(cover, Steganography.Payload.text(fits), PW), PW).text());
        IllegalArgumentException tooBig = assertThrows(IllegalArgumentException.class,
                () -> stego.hide(cover, Steganography.Payload.text(fits + "b"), PW));
        assertTrue(tooBig.getMessage().contains("can hold"));
        assertTrue(Steganography.capacityBytes(40, 40, "a-long-file-name.txt") < cap, "file names use space too");
        assertEquals(0, Steganography.capacityBytes(2, 2, null));
    }

    @Test
    void passwordIsRequired() {
        BufferedImage cover = photoLike(40, 40, BufferedImage.TYPE_INT_RGB);
        assertThrows(IllegalArgumentException.class, () -> stego.hide(cover, Steganography.Payload.text("x"), new char[0]));
    }

    @Test
    void hiddenFileNamesCantEscapeTheSaveFolder() {
        assertEquals("passwd", Steganography.safeFileName("../../etc/passwd"));
        assertEquals("evil.exe", Steganography.safeFileName("C:\\Windows\\evil.exe"));
        assertEquals("hidden-file.bin", Steganography.safeFileName(".."));
        assertEquals("hidden-file.bin", Steganography.safeFileName("dir/"));
        assertEquals("ok.txt", Steganography.safeFileName("ok.txt"));
    }
}
