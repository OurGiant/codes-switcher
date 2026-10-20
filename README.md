# GPG Decryptor & Universal Encoder/Decoder

A Java Swing desktop application combining two cryptography utilities: a GPG file decryptor and a universal text encoder/decoder.

## Tools

### GPG File Decryptor
Decrypt GPG-encrypted files through a graphical interface. Automatically detects the installed GPG version, validates it meets the minimum requirement (2.4.8), and can download and install GPG if it is not present.

### Universal Encoder/Decoder
Encode and decode text using a wide range of formats from a single interface.

**Supported formats:**
- Base64, Base32 (RFC 4648), Base58 (Bitcoin alphabet), ASCII85
- URL encoding
- HTML entities
- Hexadecimal
- Binary
- ROT13
- JSON escape
- Unicode escapes (`\uXXXX`; decode also accepts `\u{1F510}`)
- Gzip and raw Deflate (compressed bytes shown as Base64; decompression capped at 64 MB)
- JWT (decode only)
- SHA-256 / SHA-512 / SHA3-256 / SHA3-512 / BLAKE2b-512 hashing, plus SHA-1 and MD5 for legacy checks

**HMAC tab:** HMAC-SHA256/384/512 (and legacy SHA-1) of a message with a text, hex or Base64 key. Shows hex, Base64 and Base64URL, and compares against a pasted expected value.

**Cipher tabs:**
- **AES / ChaCha20** — password-based AES-256-GCM or ChaCha20-Poly1305. The key comes from PBKDF2-HMAC-SHA256 (600,000 iterations, random salt) and each encryption uses a random nonce. Output is one Base64 string holding everything needed to decrypt except the password; a wrong password or any change to the data is detected and reported.
- **Blowfish** — legacy Blowfish (ECB, hex output, optional CRC framing) for working with existing data. Not suitable for protecting new secrets.

### JWT / X.509 Inspector
A third tool for signature verification and certificate inspection — extends beyond the Encoder/Decoder's JWT decode-only support.

**JWT Verifier:**
- HMAC (HS256/384/512) verification against a shared secret, RSA/EC (RS256/384/512, ES256/384/512) against a pasted PEM public key or a JWKS URL
- Explicitly rejects `alg: none`, and refuses to verify a token whose algorithm doesn't match the family of key material you provided (e.g. an HS256 token against an RSA public key) — this is a structural defense against algorithm-confusion attacks (RFC 8725 §3.1/3.2), not just a warning
- `exp`/`nbf` checked against the current time — valid / expired / not-yet-valid / no time claims, not just raw decode

**X.509 Certificate Inspector:**
- Parses a pasted PEM certificate (or a concatenated chain: leaf, intermediate(s), root)
- Shows subject, issuer, validity window, SANs, key usage, and SHA-256 fingerprint
- Flags expired, self-signed (with an independent self-signature check, not just subject==issuer), and weak-key (RSA < 2048 bits, EC < 224-bit curve) certificates
- Basic chain validation when more than one certificate is supplied — verifies each certificate's signature against the next one's public key

## Prerequisites

- Java 24 or higher
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

One window opens with every tool in a sidebar, grouped as Encode / Decode, Ciphers, JWT,
Certificates and GPG. It reopens on the screen, size and position you last used.

- **Find a tool:** Ctrl+K (⌘K on macOS), type, press Enter.
- **Jump to a group:** Ctrl/⌘+1 … 5.
- **Use two tools side by side:** "Open in New Window" on any screen; close that window to bring it back.
- **Drop files** onto any input: text boxes load the file (Text Codecs reads binary files as raw bytes; the X.509 input also takes DER, PKCS#12, JKS and CSR files), file-path fields fill in the path.
- **Right-click any text box** for Cut / Copy / Paste and **Copy As** plain text, JSON/JavaScript, Java or Python string, or a Markdown code block.

To start on a particular screen, pass `--tool`:

```bash
java -jar target/decrypter-all.jar --tool=gpg      # also: jwt, jwt-builder, x509, keygen, hash, recipe, hmac, aes, blowfish …
```

The old per-tool classes still work as entry points and open the main window on their screen:

```bash
java -cp target/decrypter-all.jar com.ourgiant.crypt.GPGDecryptor
java -cp target/decrypter-all.jar com.ourgiant.crypt.EncodingDecodingApp
```

Help > About shows the running version and checks GitHub
Releases for a newer one (manually, or silently and non-blockingly on
startup, at most once per newly-released version).

## Native installers

Tagged releases (`v*`) trigger a GitHub Actions matrix
(`.github/workflows/build.yml`) that builds a Windows installer, a macOS
universal `.dmg`, and a Linux `.deb` via `jpackage`, and publishes them to
a GitHub Release. Icon assets live in `src/packaging/` (`.ico`, `.icns`,
and `linux/app-icon.png`); the Linux `.deb` build also uses
`src/packaging/linux/codes-switcher.desktop` and `postinst`/`prerm`
scripts for its desktop-entry integration.

## Project Structure

```
src/main/java/com/ourgiant/crypt/
├── AppLauncher.java           # Entry point (--tool=…), shared menu/icon helpers
├── MainWindow.java            # Single window: grouped sidebar + screens, pop-out windows
├── ScreenCatalog.java         # Sidebar groups, search and --tool names (no Swing)
├── AppVersion.java            # Reads the app's own version at runtime
├── AppPreferences.java        # Local app state (update notice, theme, window layout)
├── AboutDialog.java           # Help > About: version + update check
├── ThemeManager.java          # FlatLaf theme selection/persistence
├── GPGDecryptor.java          # GPG file decryption UI (thin, delegates to gpg/)
├── GpgVersion.java            # GPG version comparison logic
├── TextCodec.java             # Encoding/decoding/hashing logic
├── EncodingDecodingApp.java   # Universal encoder/decoder UI
├── CryptoInspectorApp.java    # JWT Verifier + X.509 Inspector UI (two tabs)
├── gpg/
│   ├── GpgOperations.java        # GPG install/decrypt domain logic (no Swing)
│   ├── GpgProgressListener.java  # Progress callback interface
│   └── ProcessStarter.java       # Injectable process-starting seam (for tests)
├── crypto/
│   ├── jwt/                      # JwtParser, HmacVerifier, RsaEcVerifier, PemPublicKeys,
│   │                              # JwksKeys/JwksFetcher, JwtVerification (orchestrator) -
│   │                              # no Swing
│   └── cert/                     # X509Inspector, ChainValidator - no Swing
└── util/
    ├── UpdateChecker.java        # GitHub releases API check (no Swing)
    ├── HttpClientFactory.java    # HttpClient w/ Windows trust-store support
    └── NetworkFetchException.java
```

## Dependencies

- [FlatLaf](https://www.formdev.com/flatlaf/) 3.7.2 (+ `flatlaf-intellij-themes`, `flatlaf-extras`) — UI theming
- [SLF4J](https://www.slf4j.org/) 2.0.16 + [Logback](https://logback.qos.ch/) 1.6.1 — logging
- [Jackson Databind](https://github.com/FasterXML/jackson-databind) 2.18.9 — parses the GitHub releases API response, JWT header/payload JSON, and JWKS documents
- No new dependency for JWT/X.509 crypto itself — `java.security`/`javax.crypto`/`java.security.cert` (JDK-only) cover HMAC/RSA/EC signature verification, JWK reconstruction, and certificate parsing
- [JUnit Jupiter](https://junit.org/junit5/) 5.10.2 — test scope only
- [Mockito](https://site.mockito.org/) 5.23.0 — test scope only

## License

See LICENSE file for details.
