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

A launcher window opens letting you choose between the GPG Decryptor and the Encoder/Decoder. To skip the launcher and open a tool directly:

```bash
java -cp target/decrypter-all.jar com.ourgiant.crypt.GPGDecryptor
java -cp target/decrypter-all.jar com.ourgiant.crypt.EncodingDecodingApp
```

Every window's Help > About shows the running version and checks GitHub
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
├── AppLauncher.java           # Tool picker / entry point
├── AppVersion.java            # Reads the app's own version at runtime
├── AppPreferences.java        # Local app state (last-notified update version, theme)
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
