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
├── gpg/
│   ├── GpgOperations.java        # GPG install/decrypt domain logic (no Swing)
│   ├── GpgProgressListener.java  # Progress callback interface
│   └── ProcessStarter.java       # Injectable process-starting seam (for tests)
└── util/
    ├── UpdateChecker.java        # GitHub releases API check (no Swing)
    ├── HttpClientFactory.java    # HttpClient w/ Windows trust-store support
    └── NetworkFetchException.java
```

## Dependencies

- [FlatLaf](https://www.formdev.com/flatlaf/) 3.7.2 (+ `flatlaf-intellij-themes`, `flatlaf-extras`) — UI theming
- [SLF4J](https://www.slf4j.org/) 2.0.16 + [Logback](https://logback.qos.ch/) 1.6.1 — logging
- [Jackson Databind](https://github.com/FasterXML/jackson-databind) 2.18.9 — parses the GitHub releases API response
- [JUnit Jupiter](https://junit.org/junit5/) 5.10.2 — test scope only
- [Mockito](https://site.mockito.org/) 5.23.0 — test scope only

## License

See LICENSE file for details.
