package com.ourgiant.crypt.crypto.jwt;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Converts between the two ECDSA signature encodings that matter here: JWS's raw, fixed-length
 * {@code R || S} concatenation (what an ES256/384/512-signed JWT actually carries), and the
 * ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} encoding {@link java.security.Signature}
 * requires. Getting this conversion wrong doesn't throw - it just makes every otherwise-valid
 * EC-signed token fail verification, which is a dangerous way for a security tool to be broken
 * (see JwtParserTest/RsaEcVerifierTest for round-trip coverage against real generated keys).
 */
final class EcdsaSignatureFormat {

    private EcdsaSignatureFormat() {
    }

    /** fieldSizeBytes: 32 for P-256 (ES256), 48 for P-384 (ES384), 66 for P-521 (ES512). */
    static byte[] rawToDer(byte[] raw, int fieldSizeBytes) {
        if (raw.length != 2 * fieldSizeBytes) {
            throw new IllegalArgumentException(
                "Expected a " + (2 * fieldSizeBytes) + "-byte raw ECDSA signature, got " + raw.length);
        }
        byte[] r = Arrays.copyOfRange(raw, 0, fieldSizeBytes);
        byte[] s = Arrays.copyOfRange(raw, fieldSizeBytes, 2 * fieldSizeBytes);

        byte[] rEncoded = derInteger(r);
        byte[] sEncoded = derInteger(s);

        ByteArrayOutputStream sequenceBody = new ByteArrayOutputStream();
        sequenceBody.writeBytes(rEncoded);
        sequenceBody.writeBytes(sEncoded);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30); // SEQUENCE tag
        writeLength(out, sequenceBody.size());
        out.writeBytes(sequenceBody.toByteArray());
        return out.toByteArray();
    }

    /** Inverse of rawToDer - used by tests to build raw-format fixtures from JDK-signed DER signatures. */
    static byte[] derToRaw(byte[] der, int fieldSizeBytes) {
        int idx = 0;
        if (der[idx++] != 0x30) {
            throw new IllegalArgumentException("Expected a DER SEQUENCE");
        }
        idx = skipLength(der, idx);
        byte[] r = readDerInteger(der, idx, fieldSizeBytes);
        idx = advancePastInteger(der, idx);
        byte[] s = readDerInteger(der, idx, fieldSizeBytes);

        byte[] raw = new byte[2 * fieldSizeBytes];
        System.arraycopy(r, 0, raw, 0, fieldSizeBytes);
        System.arraycopy(s, 0, raw, fieldSizeBytes, fieldSizeBytes);
        return raw;
    }

    private static byte[] derInteger(byte[] unsignedBigEndian) {
        int firstNonZero = 0;
        while (firstNonZero < unsignedBigEndian.length - 1 && unsignedBigEndian[firstNonZero] == 0) {
            firstNonZero++;
        }
        byte[] trimmed = Arrays.copyOfRange(unsignedBigEndian, firstNonZero, unsignedBigEndian.length);

        boolean needsPadding = (trimmed[0] & 0x80) != 0;
        byte[] value = trimmed;
        if (needsPadding) {
            value = new byte[trimmed.length + 1];
            value[0] = 0x00;
            System.arraycopy(trimmed, 0, value, 1, trimmed.length);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x02); // INTEGER tag
        writeLength(out, value.length);
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        byte[] lengthBytes = toMinimalBigEndian(length);
        out.write(0x80 | lengthBytes.length);
        out.writeBytes(lengthBytes);
    }

    private static byte[] toMinimalBigEndian(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int remaining = value;
        java.util.List<Byte> bytes = new java.util.ArrayList<>();
        while (remaining > 0) {
            bytes.add(0, (byte) (remaining & 0xFF));
            remaining >>>= 8;
        }
        for (byte b : bytes) {
            out.write(b);
        }
        return out.toByteArray();
    }

    // --- DER parsing helpers for derToRaw (test-fixture support only) ---

    private static int skipLength(byte[] der, int idx) {
        int lenByte = der[idx++] & 0xFF;
        if ((lenByte & 0x80) == 0) {
            return idx; // short form, length itself already consumed
        }
        int numLenBytes = lenByte & 0x7F;
        return idx + numLenBytes;
    }

    private static byte[] readDerInteger(byte[] der, int idx, int fieldSizeBytes) {
        if (der[idx++] != 0x02) {
            throw new IllegalArgumentException("Expected a DER INTEGER");
        }
        int lenByte = der[idx++] & 0xFF;
        int len;
        if ((lenByte & 0x80) == 0) {
            len = lenByte;
        } else {
            int numLenBytes = lenByte & 0x7F;
            len = 0;
            for (int i = 0; i < numLenBytes; i++) {
                len = (len << 8) | (der[idx++] & 0xFF);
            }
        }
        byte[] value = Arrays.copyOfRange(der, idx, idx + len);
        // Strip a leading 0x00 sign-padding byte, then left-pad to the fixed field size.
        int start = (value.length > fieldSizeBytes && value[0] == 0) ? 1 : 0;
        byte[] trimmed = Arrays.copyOfRange(value, start, value.length);
        byte[] padded = new byte[fieldSizeBytes];
        System.arraycopy(trimmed, 0, padded, fieldSizeBytes - trimmed.length, trimmed.length);
        return padded;
    }

    private static int advancePastInteger(byte[] der, int idx) {
        idx++; // tag
        int lenByte = der[idx++] & 0xFF;
        int len;
        if ((lenByte & 0x80) == 0) {
            len = lenByte;
        } else {
            int numLenBytes = lenByte & 0x7F;
            len = 0;
            for (int i = 0; i < numLenBytes; i++) {
                len = (len << 8) | (der[idx++] & 0xFF);
            }
        }
        return idx + len;
    }
}
