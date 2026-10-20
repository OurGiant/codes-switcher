package com.ourgiant.crypt.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Password-based authenticated encryption with AES-256-GCM or ChaCha20-Poly1305.
 *
 * <p>The key is derived from the password with PBKDF2-HMAC-SHA256 and a random
 * salt; every encryption uses a fresh random nonce. The result is one Base64
 * string that carries everything decryption needs except the password:
 *
 * <pre>
 *   magic "CS" (2) | version (1) | algorithm id (1) | iterations (4, big-endian)
 *   | salt (16) | nonce (12) | ciphertext + 16-byte tag
 * </pre>
 *
 * The header bytes are bound to the ciphertext as associated data, so changing
 * any of them makes decryption fail.
 */
public final class PasswordCipher {

    /** Supported algorithms. The id is written into the output header. */
    public enum Algorithm {
        AES_256_GCM(1, "AES-256-GCM"),
        CHACHA20_POLY1305(2, "ChaCha20-Poly1305");

        private final int id;
        private final String displayName;

        Algorithm(int id, String displayName) {
            this.id = id;
            this.displayName = displayName;
        }

        public String displayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }

        static Algorithm fromId(int id) {
            for (Algorithm a : values()) {
                if (a.id == id) {
                    return a;
                }
            }
            throw new IllegalArgumentException("Unknown algorithm id " + id + " in encrypted data");
        }
    }

    /** OWASP 2023 recommendation for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 600_000;

    /** Upper bound accepted on decrypt, so crafted input can't stall the app. */
    static final int MAX_ITERATIONS = 10_000_000;

    private static final byte[] MAGIC = {'C', 'S'};
    private static final int VERSION = 1;
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;
    private static final int KEY_BITS = 256;
    private static final int HEADER_LEN = MAGIC.length + 1 + 1 + 4 + SALT_LEN + NONCE_LEN;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int iterations;

    public PasswordCipher() {
        this(DEFAULT_ITERATIONS);
    }

    /**
     * A cipher with a custom PBKDF2 iteration count. Meant for tests, which need fast key derivation;
     * app code uses {@link #PasswordCipher()} with {@link #DEFAULT_ITERATIONS}. Decryption always uses
     * the count stored in the data.
     */
    public PasswordCipher(int iterations) {
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range: " + iterations);
        }
        this.iterations = iterations;
    }

    /** Thrown when the password is wrong or the data was modified. */
    public static final class AuthenticationException extends GeneralSecurityException {
        AuthenticationException() {
            super("Wrong password, or the encrypted data was modified");
        }
    }

    public String encrypt(String plaintext, char[] password, Algorithm algorithm) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(
                encryptBytes(plaintext.getBytes(StandardCharsets.UTF_8), password, algorithm));
    }

    public String decrypt(String encoded, char[] password) throws GeneralSecurityException {
        byte[] data;
        try {
            data = Base64.getMimeDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input is not valid Base64");
        }
        return new String(decryptBytes(data, password), StandardCharsets.UTF_8);
    }

    /** Raw-bytes form of {@link #encrypt}: same format, without the Base64 wrapping. */
    public byte[] encryptBytes(byte[] plaintext, char[] password, Algorithm algorithm) throws GeneralSecurityException {
        requirePassword(password);
        byte[] salt = randomBytes(SALT_LEN);
        byte[] nonce = randomBytes(NONCE_LEN);

        ByteBuffer header = ByteBuffer.allocate(HEADER_LEN);
        header.put(MAGIC).put((byte) VERSION).put((byte) algorithm.id).putInt(iterations).put(salt).put(nonce);
        byte[] headerBytes = header.array();

        byte[] key = deriveKey(password, salt, iterations);
        try {
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, algorithm, key, nonce);
            cipher.updateAAD(headerBytes);
            byte[] ct = cipher.doFinal(plaintext);

            byte[] out = Arrays.copyOf(headerBytes, headerBytes.length + ct.length);
            System.arraycopy(ct, 0, out, headerBytes.length, ct.length);
            return out;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Raw-bytes form of {@link #decrypt}. */
    public byte[] decryptBytes(byte[] data, char[] password) throws GeneralSecurityException {
        requirePassword(password);
        if (data.length < HEADER_LEN + TAG_LEN
                || data[0] != MAGIC[0] || data[1] != MAGIC[1]) {
            throw new IllegalArgumentException("Input was not produced by this tool (missing header)");
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.position(MAGIC.length);
        int version = buf.get() & 0xff;
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported format version " + version);
        }
        Algorithm algorithm = Algorithm.fromId(buf.get() & 0xff);
        int iters = buf.getInt();
        if (iters < 1 || iters > MAX_ITERATIONS) {
            throw new IllegalArgumentException("Iteration count in encrypted data is out of range: " + iters);
        }
        byte[] salt = new byte[SALT_LEN];
        buf.get(salt);
        byte[] nonce = new byte[NONCE_LEN];
        buf.get(nonce);

        byte[] key = deriveKey(password, salt, iters);
        try {
            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, algorithm, key, nonce);
            cipher.updateAAD(data, 0, HEADER_LEN);
            return cipher.doFinal(data, HEADER_LEN, data.length - HEADER_LEN);
        } catch (AEADBadTagException e) {
            throw new AuthenticationException();
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Bytes {@link #encryptBytes} adds to the plaintext (header + authentication tag). */
    public static int overheadBytes() {
        return HEADER_LEN + TAG_LEN;
    }

    /** Reads which algorithm an encrypted string uses, without decrypting it. */
    public static Algorithm algorithmOf(String encoded) {
        byte[] data = Base64.getMimeDecoder().decode(encoded.trim());
        if (data.length < 4 || data[0] != MAGIC[0] || data[1] != MAGIC[1]) {
            throw new IllegalArgumentException("Input was not produced by this tool (missing header)");
        }
        return Algorithm.fromId(data[3] & 0xff);
    }

    private static Cipher initCipher(int mode, Algorithm algorithm, byte[] key, byte[] nonce)
            throws GeneralSecurityException {
        Cipher cipher;
        SecretKeySpec keySpec;
        AlgorithmParameterSpec params;
        switch (algorithm) {
            case AES_256_GCM -> {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                keySpec = new SecretKeySpec(key, "AES");
                params = new GCMParameterSpec(TAG_LEN * 8, nonce);
            }
            case CHACHA20_POLY1305 -> {
                cipher = Cipher.getInstance("ChaCha20-Poly1305");
                keySpec = new SecretKeySpec(key, "ChaCha20");
                params = new IvParameterSpec(nonce);
            }
            default -> throw new IllegalStateException("Unhandled algorithm " + algorithm);
        }
        cipher.init(mode, keySpec, params);
        return cipher;
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("A password is required");
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }
}
