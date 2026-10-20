package com.ourgiant.crypt.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Standard Blowfish-CBC (as used by OpenSSL {@code bf-cbc}, PHP mcrypt, etc.) via the JDK's
 * SunJCE provider. Unlike {@link BlowfishCodec}, this works on raw bytes with an explicit IV,
 * so it interoperates with data produced by other tools.
 */
public final class BlowfishCbc {

    public static final int BLOCK = 8;
    public static final int MIN_KEY_BYTES = 4;
    public static final int MAX_KEY_BYTES = 56;

    public enum Padding {
        PKCS5("PKCS#5"), ZERO("Zero bytes"), NONE("None");

        private final String label;

        Padding(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public enum Encoding {
        HEX("Hex"), BASE64("Base64");

        private final String label;

        Encoding(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }

        public String format(byte[] b) {
            return this == HEX ? HexFormat.of().withUpperCase().formatHex(b) : Base64.getEncoder().encodeToString(b);
        }

        public byte[] parse(String s) {
            String t = s.replaceAll("\\s+", "");
            try {
                return this == HEX ? HexFormat.of().parseHex(t) : Base64.getDecoder().decode(t);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Input is not valid " + label + ": " + e.getMessage());
            }
        }
    }

    private BlowfishCbc() {
    }

    public static byte[] randomIv() {
        byte[] iv = new byte[BLOCK];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] parseIv(String hex) {
        byte[] iv;
        try {
            iv = HexFormat.of().parseHex(hex.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("IV must be hex: " + e.getMessage());
        }
        if (iv.length != BLOCK) {
            throw new IllegalArgumentException("IV must be exactly 8 bytes (16 hex digits), got " + iv.length);
        }
        return iv;
    }

    public static String encrypt(String plaintext, byte[] key, byte[] iv, Padding padding, Encoding out)
            throws GeneralSecurityException {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        if (padding == Padding.ZERO) {
            data = Arrays.copyOf(data, roundUp(data.length));
        } else if (padding == Padding.NONE && data.length % BLOCK != 0) {
            throw new IllegalArgumentException("With no padding, the input must be a multiple of 8 bytes (it is "
                    + data.length + ")");
        }
        return out.format(cipher(Cipher.ENCRYPT_MODE, key, iv, padding).doFinal(data));
    }

    public static String decrypt(String ciphertext, byte[] key, byte[] iv, Padding padding, Encoding in)
            throws GeneralSecurityException {
        byte[] data = in.parse(ciphertext);
        if (data.length == 0 || data.length % BLOCK != 0) {
            throw new IllegalArgumentException("Ciphertext must be a non-empty multiple of 8 bytes (it is "
                    + data.length + ")");
        }
        byte[] plain;
        try {
            plain = cipher(Cipher.DECRYPT_MODE, key, iv, padding).doFinal(data);
        } catch (javax.crypto.BadPaddingException e) {
            throw new IllegalArgumentException("Bad padding: wrong key, IV or padding setting");
        }
        if (padding == Padding.ZERO) {
            int end = plain.length;
            while (end > 0 && plain[end - 1] == 0) {
                end--;
            }
            plain = Arrays.copyOf(plain, end);
        }
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static Cipher cipher(int mode, byte[] key, byte[] iv, Padding padding) throws GeneralSecurityException {
        if (key.length < MIN_KEY_BYTES || key.length > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("Blowfish keys must be 4–56 bytes (got " + key.length + ")");
        }
        if (iv.length != BLOCK) {
            throw new IllegalArgumentException("IV must be exactly 8 bytes");
        }
        String transform = padding == Padding.PKCS5 ? "Blowfish/CBC/PKCS5Padding" : "Blowfish/CBC/NoPadding";
        Cipher c = Cipher.getInstance(transform);
        c.init(mode, new SecretKeySpec(key, "Blowfish"), new IvParameterSpec(iv));
        return c;
    }

    private static int roundUp(int n) {
        return n == 0 ? BLOCK : (n + BLOCK - 1) / BLOCK * BLOCK;
    }
}
