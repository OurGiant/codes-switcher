# GPG Decryptor & Universal Encoder/Decoder

A Java Swing desktop application combining two cryptography utilities: a GPG file decryptor and a universal text encoder/decoder.

## Tools

### GPG File Decryptor
Decrypt GPG-encrypted files through a graphical interface. Automatically detects the installed GPG version, validates it meets the minimum requirement (2.4.8), and can download and install GPG if it is not present.

### Universal Encoder/Decoder
Encode and decode text using a wide range of formats from a single interface.

**Supported formats:**
- Base64
- URL encoding
- HTML entities
- Hexadecimal
- Binary
- ROT13
- JSON escape
- JWT (decode only)
- SHA-256 / SHA-512 / MD5 hashing

## Prerequisites

- Java 21 or higher
- GPG 2.4.8+ (GPG Decryptor only — the app can install it if missing)

## Build

```bash
mvn clean package
```

Produces `target/decrypter-all.jar`.

## Run

```bash
java -jar target/decrypter-all.jar
```

A launcher window opens letting you choose between the GPG Decryptor and the Encoder/Decoder. To skip the launcher and open a tool directly:

```bash
java -cp target/decrypter-all.jar com.ourgiant.crypt.GPGDecryptor
java -cp target/decrypter-all.jar com.ourgiant.crypt.EncodingDecodingApp
```

## Project Structure

```
src/main/java/com/ourgiant/crypt/
├── AppLauncher.java           # Tool picker / entry point
├── GPGDecryptor.java          # GPG file decryption UI
└── EncodingDecodingApp.java   # Universal encoder/decoder UI
```

## License

See LICENSE file for details.
