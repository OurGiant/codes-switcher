package com.ourgiant.crypt.crypto.stego;

import com.ourgiant.crypt.crypto.PasswordCipher;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CourierKeyTest {

    private static BufferedImage frame(int seed) {
        BufferedImage img = new BufferedImage(40, 30, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 30; y++) {
            for (int x = 0; x < 40; x++) {
                img.setRGB(x, y, (x * 6 + seed * 31) << 16 | (y * 8 + seed) << 8 | ((x + y + seed * 7) & 0xff));
            }
        }
        return img;
    }

    private static BufferedImage reencode(BufferedImage img, String format) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertTrue(ImageIO.write(img, format, out));
        return ImageIO.read(new ByteArrayInputStream(out.toByteArray()));
    }

    private final BufferedImage a = frame(1);
    private final BufferedImage b = frame(2);
    private final BufferedImage c = frame(3);

    @Test
    void keyIsStableAndOrderDoesNotMatter() {
        char[] k = CourierKey.derive(List.of(a, b, c));
        assertEquals(64, k.length);
        assertArrayEquals(k, CourierKey.derive(List.of(c, a, b)));
        assertArrayEquals(k, CourierKey.derive(List.of(b, c, a)));
    }

    @Test
    void losslessReSaveKeepsTheKey() throws Exception {
        char[] k = CourierKey.derive(List.of(a, b, c));
        assertArrayEquals(k, CourierKey.derive(List.of(reencode(a, "png"), reencode(b, "bmp"), c)));
    }

    @Test
    void anyChangedPixelOrDifferentImageChangesTheKey() {
        char[] k = CourierKey.derive(List.of(a, b, c));
        BufferedImage tweaked = frame(3);
        tweaked.setRGB(10, 10, tweaked.getRGB(10, 10) ^ 1);
        assertFalse(java.util.Arrays.equals(k, CourierKey.derive(List.of(a, b, tweaked))));
        assertFalse(java.util.Arrays.equals(k, CourierKey.derive(List.of(a, b, frame(4)))));
    }

    @Test
    void sizeIsPartOfTheFingerprint() {
        BufferedImage wide = new BufferedImage(4, 1, BufferedImage.TYPE_INT_RGB);
        BufferedImage tall = new BufferedImage(1, 4, BufferedImage.TYPE_INT_RGB);
        assertFalse(java.util.Arrays.equals(CourierKey.fingerprint(wide), CourierKey.fingerprint(tall)));
    }

    @Test
    void needsThreeDifferentImages() {
        assertThrows(IllegalArgumentException.class, () -> CourierKey.derive(List.of(a, b)));
        assertThrows(IllegalArgumentException.class, () -> CourierKey.derive(List.of(a, b, c, frame(4))));
        // The same pixels count as the same image, even from different files.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CourierKey.derive(List.of(a, b, frame(1))));
        assertTrue(e.getMessage().contains("different"));
    }

    @Test
    void roundTripThroughSteganography() throws Exception {
        Steganography stego = new Steganography(new PasswordCipher(1_000), 1_000);
        BufferedImage cover = SteganographyTest.photoLike(200, 150, BufferedImage.TYPE_INT_RGB);
        BufferedImage out = SteganographyTest.viaPng(
                stego.hide(cover, Steganography.Payload.text("the package is secure"), CourierKey.derive(List.of(a, b, c))));

        assertEquals("the package is secure", stego.reveal(out, CourierKey.derive(List.of(c, b, a))).text());
        assertThrows(Steganography.NotFoundException.class,
                () -> stego.reveal(out, CourierKey.derive(List.of(a, b, frame(9)))));
    }
}
