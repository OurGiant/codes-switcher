package com.ourgiant.crypt;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class TextCodec {

    public static final String BASE64 = "Base64";
    public static final String URL = "URL";
    public static final String HTML = "HTML";
    public static final String HEX = "Hexadecimal";
    public static final String BINARY = "Binary";
    public static final String ROT13 = "ROT13";
    public static final String SHA256 = "SHA-256 (Hash)";
    public static final String SHA512 = "SHA-512 (Hash)";
    public static final String MD5 = "MD5 (Hash)";
    public static final String JSON = "JSON Escape";
    public static final String JWT = "JWT (Decode Only)";

    private TextCodec() {
    }

    public static String encode(String input, String method) throws Exception {
        switch (method) {
            case BASE64:
                return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));

            case URL:
                return URLEncoder.encode(input, StandardCharsets.UTF_8.toString());

            case HTML:
                return htmlEncode(input);

            case HEX:
                return bytesToHex(input.getBytes(StandardCharsets.UTF_8));

            case BINARY:
                return stringToBinary(input);

            case ROT13:
                return rot13(input);

            case JSON:
                return jsonEscape(input);

            case JWT:
                throw new UnsupportedOperationException("JWT encoding not supported - use a proper JWT library for token creation");

            case SHA256:
                return hashString(input, "SHA-256");

            case SHA512:
                return hashString(input, "SHA-512");

            case MD5:
                return hashString(input, "MD5");

            default:
                throw new IllegalArgumentException("Unknown encoding method: " + method);
        }
    }

    public static String decode(String input, String method) throws Exception {
        switch (method) {
            case BASE64:
                return new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8);

            case URL:
                return URLDecoder.decode(input, StandardCharsets.UTF_8.toString());

            case HTML:
                return htmlDecode(input);

            case HEX:
                return new String(hexToBytes(input), StandardCharsets.UTF_8);

            case BINARY:
                return binaryToString(input);

            case ROT13:
                return rot13(input); // ROT13 is its own inverse

            case JSON:
                return jsonUnescape(input);

            case JWT:
                return decodeJWT(input);

            case SHA256:
            case SHA512:
            case MD5:
                throw new UnsupportedOperationException("Hash functions cannot be decoded (one-way only)");

            default:
                throw new IllegalArgumentException("Unknown decoding method: " + method);
        }
    }

    public static String htmlEncode(String input) {
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;")
                   .replace("/", "&#x2F;");
    }

    public static String htmlDecode(String input) {
        return input.replace("&amp;", "&")
                   .replace("&lt;", "<")
                   .replace("&gt;", ">")
                   .replace("&quot;", "\"")
                   .replace("&#x27;", "'")
                   .replace("&#x2F;", "/");
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static byte[] hexToBytes(String hex) throws Exception {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    public static String stringToBinary(String input) {
        StringBuilder binary = new StringBuilder();
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            binary.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return binary.toString();
    }

    public static String binaryToString(String binary) throws Exception {
        if (binary.length() % 8 != 0) {
            throw new IllegalArgumentException("Binary string length must be divisible by 8");
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteString = binary.substring(i, i + 8);
            int byteValue = Integer.parseInt(byteString, 2);
            result.append((char) byteValue);
        }
        return result.toString();
    }

    public static String rot13(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    public static String jsonEscape(String input) {
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\b", "\\b")
                   .replace("\f", "\\f")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t")
                   .replace("/", "\\/");
    }

    public static String jsonUnescape(String input) {
        return input.replace("\\\\", "\\")
                   .replace("\\\"", "\"")
                   .replace("\\b", "\b")
                   .replace("\\f", "\f")
                   .replace("\\n", "\n")
                   .replace("\\r", "\r")
                   .replace("\\t", "\t")
                   .replace("\\/", "/");
    }

    public static String hashString(String input, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static String decodeJWT(String jwt) throws Exception {
        // Remove any whitespace
        jwt = jwt.trim();

        // JWT format: header.payload.signature
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format. Expected 3 parts separated by dots, got " + parts.length);
        }

        StringBuilder result = new StringBuilder();

        try {
            // Decode header
            String header = decodeJWTPart(parts[0]);
            result.append("=== JWT HEADER ===\n");
            result.append(formatJSON(header));
            result.append("\n\n");

            // Decode payload
            String payload = decodeJWTPart(parts[1]);
            result.append("=== JWT PAYLOAD ===\n");
            result.append(formatJSON(payload));
            result.append("\n\n");

            // Show signature info (can't decode without key)
            result.append("=== JWT SIGNATURE ===\n");
            result.append("Raw: ").append(parts[2]).append("\n");
            result.append("Note: Signature verification requires the secret key\n");
            result.append("Length: ").append(parts[2].length()).append(" characters");

        } catch (Exception e) {
            throw new Exception("JWT decoding failed: " + e.getMessage());
        }

        return result.toString();
    }

    public static String decodeJWTPart(String part) throws Exception {
        // JWT uses Base64 URL encoding (no padding)
        // Convert to standard Base64 by adding padding if needed
        String padded = part;
        while (padded.length() % 4 != 0) {
            padded += "=";
        }

        // Replace URL-safe characters
        padded = padded.replace('-', '+').replace('_', '/');

        // Decode
        byte[] decoded = Base64.getDecoder().decode(padded);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public static String formatJSON(String json) {
        // Simple JSON formatting - add indentation
        StringBuilder formatted = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        char prev = 0;

        for (char c : json.toCharArray()) {
            if (c == '"' && prev != '\\') {
                inString = !inString;
            }

            if (!inString) {
                switch (c) {
                    case '{':
                    case '[':
                        formatted.append(c).append('\n');
                        indent++;
                        addIndent(formatted, indent);
                        break;
                    case '}':
                    case ']':
                        formatted.append('\n');
                        indent--;
                        addIndent(formatted, indent);
                        formatted.append(c);
                        break;
                    case ',':
                        formatted.append(c).append('\n');
                        addIndent(formatted, indent);
                        break;
                    case ':':
                        formatted.append(c).append(' ');
                        break;
                    default:
                        formatted.append(c);
                }
            } else {
                formatted.append(c);
            }
            prev = c;
        }

        return formatted.toString();
    }

    private static void addIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
    }
}
