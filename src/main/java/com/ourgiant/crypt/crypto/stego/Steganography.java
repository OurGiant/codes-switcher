package com.ourgiant.crypt.crypto.stego;

import com.ourgiant.crypt.crypto.PasswordCipher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Hides an encrypted message or file in the least significant bit of an image's red, green and
 * blue values, and gets it back.
 *
 * <ul>
 *   <li>The payload is encrypted with {@link PasswordCipher} (AES-256-GCM) first, so the hidden
 *       bits are indistinguishable from noise without the password and any change is detected.</li>
 *   <li>Which colour slots carry the bits is decided by a password-keyed permutation (a small
 *       Feistel network with cycle-walking), so data is scattered over the whole image without
 *       needing a shuffle table the size of the image.</li>
 *   <li>Each colour value changes by at most 1, which is invisible. Output must be saved losslessly
 *       (PNG); JPEG recompression destroys the data.</li>
 * </ul>
 * The hidden stream is {@code "CSSG" | length (4) | ciphertext}. The ciphertext holds
 * {@code kind (1) | name length (2) | name | data}.
 */
public final class Steganography {

    /** Images larger than this are refused, to keep memory use reasonable (4 bytes per pixel). */
    public static final long MAX_PIXELS = 40_000_000L;

    private static final byte[] MAGIC = {'C', 'S', 'S', 'G'};
    private static final int FRAME_HEADER = MAGIC.length + 4;
    private static final int CONTAINER_HEADER = 1 + 2;
    private static final int KIND_TEXT = 0;
    private static final int KIND_FILE = 1;
    private static final byte[] PLACEMENT_SALT = "codes-switcher/stego/placement/v1".getBytes(StandardCharsets.US_ASCII);
    static final int DEFAULT_PLACEMENT_ITERATIONS = 200_000;

    /** A hidden message: text ({@code fileName == null}) or a file with its original name. */
    public record Payload(String fileName, byte[] data) {
        public static Payload text(String text) {
            return new Payload(null, text.getBytes(StandardCharsets.UTF_8));
        }

        public static Payload file(String name, byte[] data) {
            return new Payload(name, data);
        }

        public boolean isText() {
            return fileName == null;
        }

        public String text() {
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    /** Nothing hidden with this password (or nothing hidden at all; the two look the same by design). */
    public static final class NotFoundException extends Exception {
        NotFoundException() {
            super("No hidden message found in this image for that password");
        }
    }

    /** Data was found for this password but fails its integrity check: the image was edited or recompressed. */
    public static final class DamagedException extends Exception {
        DamagedException() {
            super("Hidden data was found, but it's damaged — the image was probably edited, resized or "
                    + "saved as JPEG after the message was hidden");
        }
    }

    private final PasswordCipher cipher;
    private final int placementIterations;

    public Steganography() {
        this(new PasswordCipher(), DEFAULT_PLACEMENT_ITERATIONS);
    }

    /** For tests: lighter key derivation. */
    public Steganography(PasswordCipher cipher, int placementIterations) {
        this.cipher = cipher;
        this.placementIterations = placementIterations;
    }

    /** How many bytes of message (or file contents) fit in an image of this size, for a payload name of this length. */
    public static long capacityBytes(int width, int height, String fileName) {
        long slots = (long) width * height * 3;
        int name = fileName == null ? 0 : fileName.getBytes(StandardCharsets.UTF_8).length;
        long room = slots / 8 - FRAME_HEADER - PasswordCipher.overheadBytes() - CONTAINER_HEADER - name;
        return Math.max(0, room);
    }

    public BufferedImage hide(BufferedImage cover, Payload payload, char[] password) throws GeneralSecurityException {
        checkSize(cover);
        int w = cover.getWidth();
        int h = cover.getHeight();
        long capacity = capacityBytes(w, h, payload.fileName());
        if (payload.data().length > capacity) {
            throw new IllegalArgumentException(String.format(
                    "The message is %,d bytes but this image can hold %,d. Use a larger image or a shorter message.",
                    payload.data().length, capacity));
        }
        byte[] name = payload.fileName() == null ? new byte[0] : payload.fileName().getBytes(StandardCharsets.UTF_8);
        if (name.length > 0xffff) {
            throw new IllegalArgumentException("File name is too long");
        }
        ByteArrayOutputStream container = new ByteArrayOutputStream(CONTAINER_HEADER + name.length + payload.data().length);
        container.write(payload.isText() ? KIND_TEXT : KIND_FILE);
        container.write(name.length >> 8);
        container.write(name.length);
        container.writeBytes(name);
        container.writeBytes(payload.data());
        byte[] encrypted = cipher.encryptBytes(container.toByteArray(), password, PasswordCipher.Algorithm.AES_256_GCM);

        byte[] frame = ByteBuffer.allocate(FRAME_HEADER + encrypted.length)
                .put(MAGIC).putInt(encrypted.length).put(encrypted).array();

        int[] pixels = cover.getRGB(0, 0, w, h, null, 0, w);
        Placement place = new Placement((long) w * h * 3, placementKey(password));
        long bit = 0;
        for (byte b : frame) {
            for (int k = 7; k >= 0; k--) {
                long slot = place.slot(bit++);
                int px = (int) (slot / 3);
                int shift = 16 - 8 * (int) (slot % 3); // R=16, G=8, B=0
                int value = (b >> k) & 1;
                pixels[px] = (pixels[px] & ~(1 << shift)) | (value << shift);
            }
        }
        boolean alpha = cover.getColorModel().hasAlpha();
        BufferedImage out = new BufferedImage(w, h, alpha ? BufferedImage.TYPE_INT_ARGB : BufferedImage.TYPE_INT_RGB);
        out.setRGB(0, 0, w, h, pixels, 0, w);
        return out;
    }

    public Payload reveal(BufferedImage image, char[] password)
            throws GeneralSecurityException, NotFoundException, DamagedException {
        checkSize(image);
        int w = image.getWidth();
        int h = image.getHeight();
        long slots = (long) w * h * 3;
        if (slots / 8 < FRAME_HEADER + PasswordCipher.overheadBytes()) {
            throw new NotFoundException();
        }
        int[] pixels = image.getRGB(0, 0, w, h, null, 0, w);
        Placement place = new Placement(slots, placementKey(password));
        Reader reader = new Reader(pixels, place);

        byte[] header = reader.read(FRAME_HEADER);
        if (!Arrays.equals(Arrays.copyOf(header, MAGIC.length), MAGIC)) {
            throw new NotFoundException();
        }
        int length = ByteBuffer.wrap(header, MAGIC.length, 4).getInt();
        if (length < PasswordCipher.overheadBytes() || length > slots / 8 - FRAME_HEADER) {
            throw new DamagedException();
        }
        byte[] encrypted = reader.read(length);
        byte[] container;
        try {
            container = cipher.decryptBytes(encrypted, password);
        } catch (PasswordCipher.AuthenticationException | IllegalArgumentException e) {
            throw new DamagedException();
        }
        if (container.length < CONTAINER_HEADER) {
            throw new DamagedException();
        }
        int kind = container[0] & 0xff;
        int nameLen = ((container[1] & 0xff) << 8) | (container[2] & 0xff);
        if (CONTAINER_HEADER + nameLen > container.length) {
            throw new DamagedException();
        }
        byte[] data = Arrays.copyOfRange(container, CONTAINER_HEADER + nameLen, container.length);
        if (kind == KIND_TEXT) {
            return new Payload(null, data);
        }
        String name = new String(container, CONTAINER_HEADER, nameLen, StandardCharsets.UTF_8);
        return new Payload(safeFileName(name), data);
    }

    /** Strips any directory part so a hidden name like "../../x" can't point a save outside the chosen folder. */
    static String safeFileName(String name) {
        String base = name.replace('\\', '/');
        base = base.substring(base.lastIndexOf('/') + 1).strip();
        return base.isEmpty() || base.equals(".") || base.equals("..") ? "hidden-file.bin" : base;
    }

    private static void checkSize(BufferedImage img) {
        if ((long) img.getWidth() * img.getHeight() > MAX_PIXELS) {
            throw new IllegalArgumentException(String.format("Images over %,d megapixels aren't supported", MAX_PIXELS / 1_000_000));
        }
    }

    private long[] placementKey(char[] password) throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("A password is required");
        }
        PBEKeySpec spec = new PBEKeySpec(password, PLACEMENT_SALT, placementIterations, 256);
        try {
            byte[] k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            ByteBuffer b = ByteBuffer.wrap(k);
            return new long[]{b.getLong(), b.getLong(), b.getLong(), b.getLong()};
        } finally {
            spec.clearPassword();
        }
    }

    /** Reads bytes from consecutive positions of the placement. */
    private static final class Reader {
        private final int[] pixels;
        private final Placement place;
        private long bit;

        Reader(int[] pixels, Placement place) {
            this.pixels = pixels;
            this.place = place;
        }

        byte[] read(int n) {
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) {
                int b = 0;
                for (int k = 0; k < 8; k++) {
                    long slot = place.slot(bit++);
                    int shift = 16 - 8 * (int) (slot % 3);
                    b = (b << 1) | ((pixels[(int) (slot / 3)] >> shift) & 1);
                }
                out[i] = (byte) b;
            }
            return out;
        }
    }

    /**
     * A keyed bijection on {@code [0, n)}: a 4-round Feistel network over the smallest even-bit
     * power-of-two domain covering n, with cycle-walking for values that land outside [0, n).
     */
    static final class Placement {
        private final long n;
        private final int half;
        private final long mask;
        private final long[] keys;

        Placement(long n, long[] keys) {
            this.n = n;
            int bits = Math.max(2, 64 - Long.numberOfLeadingZeros(n - 1));
            this.half = (bits + 1) / 2;
            this.mask = (1L << half) - 1;
            this.keys = keys;
        }

        long slot(long i) {
            if (i >= n) {
                throw new IllegalStateException("Out of room in the image");
            }
            long x = i;
            do {
                x = permute(x);
            } while (x >= n);
            return x;
        }

        private long permute(long x) {
            long left = x >>> half;
            long right = x & mask;
            for (long key : keys) {
                long next = left ^ (mix(right ^ key) & mask);
                left = right;
                right = next;
            }
            return (left << half) | right;
        }

        /** SplitMix64 finaliser: a fast, well-mixed 64-bit hash. */
        private static long mix(long z) {
            z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
            z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
            return z ^ (z >>> 31);
        }
    }
}
