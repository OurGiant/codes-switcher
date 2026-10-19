package com.ourgiant.crypt.crypto.asn1;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Minimal DER reader: enough to walk structures the JDK has no public parser for (e.g. PKCS#10).
 * Only definite-length encodings are accepted, as DER requires.
 */
public final class Der {

    public static final int SEQUENCE = 0x30;
    public static final int SET = 0x31;
    public static final int INTEGER = 0x02;
    public static final int BIT_STRING = 0x03;
    public static final int OCTET_STRING = 0x04;
    public static final int NULL = 0x05;
    public static final int OID = 0x06;
    public static final int BOOLEAN = 0x01;

    private Der() {
    }

    /** Thrown for truncated or malformed DER. */
    public static final class DerException extends IllegalArgumentException {
        public DerException(String message) {
            super(message);
        }
    }

    /** One tag-length-value element. {@code encoded} covers header and content. */
    public record Node(int tag, byte[] source, int start, int headerLength, int length) {

        public int end() {
            return start + headerLength + length;
        }

        public byte[] encoded() {
            return Arrays.copyOfRange(source, start, end());
        }

        public byte[] content() {
            return Arrays.copyOfRange(source, start + headerLength, end());
        }

        public boolean constructed() {
            return (tag & 0x20) != 0;
        }

        /** Context-specific tag number for [n] tags, else -1. */
        public int contextTag() {
            return (tag & 0xC0) == 0x80 ? tag & 0x1F : -1;
        }

        public List<Node> children() {
            List<Node> out = new ArrayList<>();
            int pos = start + headerLength;
            while (pos < end()) {
                Node child = read(source, pos, end());
                out.add(child);
                pos = child.end();
            }
            return out;
        }

        public Node child(int index) {
            List<Node> c = children();
            if (index >= c.size()) {
                throw new DerException("Expected at least " + (index + 1) + " elements, found " + c.size());
            }
            return c.get(index);
        }

        public Node expect(int expectedTag) {
            if (tag != expectedTag) {
                throw new DerException(String.format("Expected tag 0x%02x but found 0x%02x", expectedTag, tag));
            }
            return this;
        }

        public String oid() {
            expect(OID);
            return decodeOid(content());
        }

        public BigInteger integer() {
            expect(INTEGER);
            return new BigInteger(content());
        }

        /** Content of a BIT STRING without the leading unused-bits byte. */
        public byte[] bitString() {
            expect(BIT_STRING);
            byte[] c = content();
            if (c.length == 0) {
                throw new DerException("Empty BIT STRING");
            }
            return Arrays.copyOfRange(c, 1, c.length);
        }
    }

    /** Reads the single top-level element and checks nothing trails it. */
    public static Node parse(byte[] der) {
        Node n = read(der, 0, der.length);
        if (n.end() != der.length) {
            throw new DerException("Unexpected " + (der.length - n.end()) + " bytes after the DER structure");
        }
        return n;
    }

    static Node read(byte[] src, int pos, int limit) {
        if (pos + 2 > limit) {
            throw new DerException("Truncated DER at offset " + pos);
        }
        int tag = src[pos] & 0xff;
        if ((tag & 0x1f) == 0x1f) {
            throw new DerException("High-tag-number form is not supported");
        }
        int first = src[pos + 1] & 0xff;
        int header = 2;
        long length;
        if (first < 0x80) {
            length = first;
        } else {
            int n = first & 0x7f;
            if (n == 0) {
                throw new DerException("Indefinite length is not allowed in DER");
            }
            if (n > 4 || pos + 2 + n > limit) {
                throw new DerException("Bad length at offset " + pos);
            }
            length = 0;
            for (int i = 0; i < n; i++) {
                length = (length << 8) | (src[pos + 2 + i] & 0xff);
            }
            header += n;
        }
        if (pos + header + length > limit) {
            throw new DerException("Element at offset " + pos + " runs past the end of its container");
        }
        return new Node(tag, src, pos, header, (int) length);
    }

    static String decodeOid(byte[] c) {
        if (c.length == 0) {
            throw new DerException("Empty OID");
        }
        StringBuilder sb = new StringBuilder();
        long value = 0;
        boolean first = true;
        for (byte b : c) {
            value = (value << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) {
                if (first) {
                    int arc1 = (int) Math.min(value / 40, 2);
                    sb.append(arc1).append('.').append(value - arc1 * 40L);
                    first = false;
                } else {
                    sb.append('.').append(value);
                }
                value = 0;
            }
        }
        return sb.toString();
    }
}
