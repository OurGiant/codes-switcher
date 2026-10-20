package com.ourgiant.crypt.crypto.stego;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * Courier Mode's key: three images instead of a password.
 *
 * <p>Each image is fingerprinted from its decoded pixels (SHA-256 over width, height and the sRGB
 * ARGB value of every pixel), so a lossless re-save such as PNG to BMP keeps the same key while any
 * changed pixel or a JPEG recompression does not. The three fingerprints are sorted, so the order the
 * images are chosen in doesn't matter, and hashed together into a 64-character key that is then used
 * exactly like a password by {@link Steganography}.
 *
 * <p>The key is only as secret as the images: anyone holding the same three files can rebuild it.
 */
public final class CourierKey {

    public static final int FRAMES = 3;

    private static final byte[] DOMAIN = "codes-switcher/courier/v1".getBytes(StandardCharsets.US_ASCII);

    private CourierKey() {
    }

    /** SHA-256 of the image's size and pixels. */
    public static byte[] fingerprint(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        if ((long) w * h > Steganography.MAX_PIXELS) {
            throw new IllegalArgumentException("Image is too large (" + w + " × " + h + ")");
        }
        MessageDigest sha = sha256();
        sha.update(ByteBuffer.allocate(8).putInt(w).putInt(h).array());
        int[] row = new int[w];
        ByteBuffer bytes = ByteBuffer.allocate(w * 4);
        for (int y = 0; y < h; y++) {
            img.getRGB(0, y, w, 1, row, 0, w);
            bytes.clear();
            bytes.asIntBuffer().put(row);
            sha.update(bytes.array());
        }
        return sha.digest();
    }

    /** The key for three different images, in any order. */
    public static char[] derive(List<BufferedImage> frames) {
        if (frames.size() != FRAMES) {
            throw new IllegalArgumentException("Courier Mode needs exactly " + FRAMES + " images");
        }
        List<byte[]> prints = new ArrayList<>();
        for (BufferedImage f : frames) {
            prints.add(fingerprint(f));
        }
        prints.sort(Arrays::compareUnsigned);
        for (int i = 1; i < prints.size(); i++) {
            if (Arrays.equals(prints.get(i - 1), prints.get(i))) {
                throw new IllegalArgumentException("The three images must be different from each other");
            }
        }
        MessageDigest sha = sha256();
        sha.update(DOMAIN);
        prints.forEach(sha::update);
        return HexFormat.of().formatHex(sha.digest()).toCharArray();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
