package com.ourgiant.crypt.crypto.asn1;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/** Minimal DER encoder for building certificates. Each method returns one complete TLV element. */
public final class DerWriter {

    private DerWriter() {
    }

    public static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int bytes = len < 0x100 ? 1 : len < 0x10000 ? 2 : len < 0x1000000 ? 3 : 4;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                out.write(len >>> (8 * i));
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    public static byte[] sequence(byte[]... items) {
        return tlv(Der.SEQUENCE, concat(items));
    }

    public static byte[] set(byte[]... items) {
        return tlv(Der.SET, concat(items));
    }

    public static byte[] integer(BigInteger value) {
        return tlv(Der.INTEGER, value.toByteArray());
    }

    public static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    public static byte[] bool(boolean value) {
        return tlv(Der.BOOLEAN, new byte[]{(byte) (value ? 0xff : 0x00)});
    }

    public static byte[] nullValue() {
        return new byte[]{Der.NULL, 0};
    }

    public static byte[] octetString(byte[] content) {
        return tlv(Der.OCTET_STRING, content);
    }

    /** BIT STRING holding whole bytes (no unused bits), e.g. a signature or public key. */
    public static byte[] bitString(byte[] content) {
        byte[] c = new byte[content.length + 1];
        System.arraycopy(content, 0, c, 1, content.length);
        return tlv(Der.BIT_STRING, c);
    }

    /**
     * Named-bit BIT STRING (e.g. KeyUsage), with trailing zero bits trimmed as DER requires.
     * Bit 0 is the most significant bit of the first byte.
     */
    public static byte[] namedBits(int... bits) {
        int max = 0;
        for (int b : bits) {
            max = Math.max(max, b);
        }
        byte[] data = new byte[max / 8 + 1];
        for (int b : bits) {
            data[b / 8] |= (byte) (0x80 >>> (b % 8));
        }
        int unused = Integer.numberOfTrailingZeros(data[data.length - 1] & 0xff);
        byte[] c = new byte[data.length + 1];
        c[0] = (byte) unused;
        System.arraycopy(data, 0, c, 1, data.length);
        return tlv(Der.BIT_STRING, c);
    }

    public static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, Long.parseLong(parts[0]) * 40 + Long.parseLong(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return tlv(Der.OID, out.toByteArray());
    }

    public static byte[] utf8String(String s) {
        return tlv(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    /** UTCTime before 2050, GeneralizedTime from 2050 on (RFC 5280 §4.1.2.5). */
    public static byte[] time(ZonedDateTime t) {
        ZonedDateTime utc = t.withZoneSameInstant(ZoneOffset.UTC);
        if (utc.getYear() < 2050) {
            return tlv(0x17, DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").format(utc).getBytes(StandardCharsets.US_ASCII));
        }
        return tlv(0x18, DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").format(utc).getBytes(StandardCharsets.US_ASCII));
    }

    /** [n] EXPLICIT wrapper around a complete element. */
    public static byte[] explicit(int n, byte[] element) {
        return tlv(0xA0 | n, element);
    }

    /** [n] IMPLICIT primitive, e.g. a GeneralName dNSName [2]. */
    public static byte[] implicitPrimitive(int n, byte[] content) {
        return tlv(0x80 | n, content);
    }

    private static void writeBase128(ByteArrayOutputStream out, long v) {
        int groups = 1;
        for (long t = v >>> 7; t != 0; t >>>= 7) {
            groups++;
        }
        for (int i = groups - 1; i >= 0; i--) {
            int b = (int) ((v >>> (7 * i)) & 0x7f);
            out.write(i == 0 ? b : b | 0x80);
        }
    }

    private static byte[] concat(byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] i : items) {
            out.writeBytes(i);
        }
        return out.toByteArray();
    }
}
