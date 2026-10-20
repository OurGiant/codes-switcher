package com.ourgiant.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/** Byte-level codecs used by {@link TextCodec}: Base32, Base58, ASCII85, gzip/deflate, Unicode escapes. */
final class ExtraCodecs {

    private ExtraCodecs() {
    }

    /** Decompressed output larger than this is refused, so a tiny "zip bomb" can't exhaust memory. */
    static final int MAX_INFLATED_BYTES = 64 * 1024 * 1024;

    // ---- Base32 (RFC 4648) ----

    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    static String base32Encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length + 4) / 5 * 8);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(B32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(B32.charAt((buffer << (5 - bits)) & 31));
        }
        while (out.length() % 8 != 0) {
            out.append('=');
        }
        return out.toString();
    }

    static byte[] base32Decode(String text) {
        String s = stripWhitespace(text).toUpperCase();
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') {
            end--;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(end * 5 / 8);
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < end; i++) {
            int v = B32.indexOf(s.charAt(i));
            if (v < 0) {
                throw new IllegalArgumentException("Invalid Base32 character '" + s.charAt(i) + "' at position " + i);
            }
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    // ---- Base58 (Bitcoin alphabet) ----

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);

    static String base58Encode(byte[] data) {
        int zeros = 0;
        while (zeros < data.length && data[zeros] == 0) {
            zeros++;
        }
        BigInteger n = new BigInteger(1, data);
        StringBuilder out = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(FIFTY_EIGHT);
            out.append(B58.charAt(qr[1].intValue()));
            n = qr[0];
        }
        out.append("1".repeat(zeros));
        return out.reverse().toString();
    }

    static byte[] base58Decode(String text) {
        String s = stripWhitespace(text);
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int v = B58.indexOf(s.charAt(i));
            if (v < 0) {
                throw new IllegalArgumentException("Invalid Base58 character '" + s.charAt(i) + "' at position " + i);
            }
            n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(v));
        }
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') {
            zeros++;
        }
        byte[] body = n.signum() == 0 ? new byte[0] : n.toByteArray();
        int skip = (body.length > 1 && body[0] == 0) ? 1 : 0; // drop BigInteger sign byte
        byte[] out = new byte[zeros + body.length - skip];
        System.arraycopy(body, skip, out, zeros, body.length - skip);
        return out;
    }

    // ---- ASCII85 (Adobe/btoa alphabet, 'z' for zero groups, optional <~ ~> on decode) ----

    static String ascii85Encode(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 5 / 4 + 5);
        for (int i = 0; i < data.length; i += 4) {
            int n = Math.min(4, data.length - i);
            long v = 0;
            for (int j = 0; j < 4; j++) {
                v = (v << 8) | (j < n ? data[i + j] & 0xff : 0);
            }
            if (v == 0 && n == 4) {
                out.append('z');
                continue;
            }
            char[] block = new char[5];
            for (int j = 4; j >= 0; j--) {
                block[j] = (char) ('!' + v % 85);
                v /= 85;
            }
            out.append(block, 0, n + 1);
        }
        return out.toString();
    }

    static byte[] ascii85Decode(String text) {
        String s = stripWhitespace(text);
        if (s.startsWith("<~")) {
            s = s.substring(2);
        }
        if (s.endsWith("~>")) {
            s = s.substring(0, s.length() - 2);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() * 4 / 5 + 4);
        long v = 0;
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 'z' && count == 0) {
                out.writeBytes(new byte[4]);
                continue;
            }
            if (c < '!' || c > 'u') {
                throw new IllegalArgumentException("Invalid ASCII85 character '" + c + "' at position " + i);
            }
            v = v * 85 + (c - '!');
            if (++count == 5) {
                if (v > 0xffffffffL) {
                    throw new IllegalArgumentException("Invalid ASCII85 group ending at position " + i);
                }
                writeInt(out, v, 4);
                v = 0;
                count = 0;
            }
        }
        if (count == 1) {
            throw new IllegalArgumentException("Truncated ASCII85 input (a final group needs at least 2 characters)");
        }
        if (count > 1) {
            for (int j = count; j < 5; j++) {
                v = v * 85 + 84;
            }
            writeInt(out, v, count - 1);
        }
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, long v, int bytes) {
        for (int j = 0; j < bytes; j++) {
            out.write((int) (v >>> (24 - 8 * j)) & 0xff);
        }
    }

    // ---- gzip / raw deflate (compressed bytes shown as Base64) ----

    static String gzipEncode(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(data);
        }
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }

    static byte[] gzipDecode(String base64) throws IOException {
        byte[] compressed = decodeBase64Input(base64);
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            return readLimited(in);
        } catch (java.util.zip.ZipException | java.io.EOFException e) {
            throw new IllegalArgumentException("Not valid gzip data: " + e.getMessage());
        }
    }

    static String deflateEncode(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try (DeflaterOutputStream out = new DeflaterOutputStream(bos, deflater)) {
            out.write(data);
        } finally {
            deflater.end();
        }
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }

    static byte[] deflateDecode(String base64) throws IOException {
        byte[] compressed = decodeBase64Input(base64);
        Inflater inflater = new Inflater(true);
        try (InputStream in = new InflaterInputStream(new ByteArrayInputStream(compressed), inflater)) {
            byte[] out = readLimited(in);
            if (!inflater.finished()) {
                throw new IllegalArgumentException("Not valid raw deflate data (stream is incomplete)");
            }
            return out;
        } catch (java.util.zip.ZipException | java.io.EOFException e) {
            throw new IllegalArgumentException("Not valid raw deflate data: " + e.getMessage());
        } finally {
            inflater.end();
        }
    }

    private static byte[] decodeBase64Input(String text) {
        try {
            return Base64.getMimeDecoder().decode(text.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Compressed input must be Base64: " + e.getMessage());
        }
    }

    private static byte[] readLimited(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            if (out.size() + n > MAX_INFLATED_BYTES) {
                throw new IllegalArgumentException("Decompressed data is larger than "
                        + (MAX_INFLATED_BYTES >> 20) + " MB; refusing to continue");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    // ---- Unicode escapes ----

    /** Escapes every char outside printable ASCII (plus backslash) as backslash-u-XXXX; newlines and tabs are kept. */
    static String unicodeEscape(String input) {
        StringBuilder out = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\\') {
                out.append("\\\\");
            } else if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t') {
                out.append(c);
            } else {
                out.append(String.format("\\u%04x", (int) c));
            }
        }
        return out.toString();
    }

    /** Reverses {@link #unicodeEscape}; also accepts the brace form backslash-u-{1F600}. */
    static String unicodeUnescape(String input) {
        StringBuilder out = new StringBuilder(input.length());
        int i = 0;
        while (i < input.length()) {
            char c = input.charAt(i);
            if (c != '\\' || i + 1 >= input.length()) {
                out.append(c);
                i++;
                continue;
            }
            char next = input.charAt(i + 1);
            if (next == '\\') {
                out.append('\\');
                i += 2;
            } else if (next == 'u' && i + 2 < input.length() && input.charAt(i + 2) == '{') {
                int close = input.indexOf('}', i + 3);
                if (close < 0) {
                    throw new IllegalArgumentException("Unclosed \\u{...} escape at position " + i);
                }
                int cp = parseHex(input.substring(i + 3, close), i);
                if (!Character.isValidCodePoint(cp)) {
                    throw new IllegalArgumentException("Invalid code point in escape at position " + i);
                }
                out.appendCodePoint(cp);
                i = close + 1;
            } else if (next == 'u') {
                if (i + 6 > input.length()) {
                    throw new IllegalArgumentException("Truncated \\u escape at position " + i);
                }
                out.append((char) parseHex(input.substring(i + 2, i + 6), i));
                i += 6;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static int parseHex(String hex, int pos) {
        if (hex.isEmpty() || hex.length() > 6) {
            throw new IllegalArgumentException("Invalid \\u escape at position " + pos);
        }
        try {
            return Integer.parseInt(hex, 16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid hex digits in \\u escape at position " + pos);
        }
    }

    private static String stripWhitespace(String s) {
        return s.replaceAll("\\s+", "");
    }

    static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
