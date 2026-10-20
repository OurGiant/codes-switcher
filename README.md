# Codes Switcher

A Java Swing desktop toolkit for everyday encoding, hashing, encryption, JWT, certificate and GPG work. Everything runs locally in one window, with every tool in a grouped sidebar.

## Tools

### Encode / Decode
- **Text Codecs** — encode and decode:
  - Base64, Base32 (RFC 4648), Base58 (Bitcoin alphabet), ASCII85, hexadecimal, binary
  - URL encoding, HTML entities, JSON escape, Unicode escapes (`\uXXXX`; decode also accepts `\u{1F510}`), ROT13
  - Gzip and raw Deflate (compressed bytes shown as Base64; decompression capped at 64 MB)
  - JWT (decode only)
  - Hashes: SHA-256 / SHA-512 / SHA3-256 / SHA3-512 / BLAKE2b-512, plus SHA-1 and MD5 for legacy checks
  - **Detect Format** guesses what pasted data is and selects it, and flags things it can't decode (PEM blocks, hash-length hex, this app's cipher output).
  - **Open File… / Save Output…** work on raw bytes, so binary files encode and decode exactly.
- **Recipe** — chain steps (e.g. Base64 → URL → gzip decode) and see each step's output. Recipes can be copied and loaded as plain text.
- **HMAC** — HMAC-SHA256/384/512 (and legacy SHA-1) with a text, hex or Base64 key. Shows hex, Base64 and Base64URL, and compares against an expected value.
- **File Hash** — hash files of any size (streamed, with progress) and check against a published hash. Accepts `sha256sum` and `SHA256 (file) = …` lines.

### Ciphers
- **AES / ChaCha20** — password-based AES-256-GCM or ChaCha20-Poly1305. The key comes from PBKDF2-HMAC-SHA256 (600,000 iterations, random salt) and each encryption uses a random nonce. Output is one Base64 string holding everything needed to decrypt except the password. A wrong password or any change to the data is detected.
- **Blowfish** — legacy mode (ECB, hex, optional CRC framing) for existing data, and standard **CBC** mode (IV, PKCS#5/zero/no padding, hex or Base64) compatible with OpenSSL `bf-cbc`. Not recommended for protecting new secrets.

### JWT
- **Verifier** — HMAC (HS256/384/512) against a shared secret, or RSA/EC (RS/ES 256/384/512) against a PEM public key or a JWKS URL.
  - Rejects `alg: none`, and refuses a token whose algorithm doesn't match the kind of key provided (algorithm-confusion defence, RFC 8725 §3.1/3.2).
  - Checks `exp`/`nbf` against the current time.
- **Builder** — create and sign tokens from header/payload JSON, with HS*, RS* or ES* keys (PEM, PKCS#8 or PKCS#1). The header's `alg` always matches the signature, and `none` is never produced. "Open in Verifier" checks the result.

### Certificates
- **X.509 Inspector** — opens:
  - PEM and DER certificates and chains;
  - PKCS#12 / JKS keystores (password prompt);
  - PKCS#10 CSRs;
  - the chain a TLS host presents.

  It shows subject, issuer, validity, SANs, key usage and SHA-256 fingerprint, and flags expired, self-signed and weak-key certificates. It also validates chains and checks that a CSR is signed by the key it contains.
- **Key Generator** — RSA 2048/3072/4096, EC P-256/P-384 and Ed25519 key pairs as PEM, plus an optional self-signed X.509 v3 certificate (SANs, validity, CA option). Export as PEM or PKCS#12.

### GPG
Uses the system `gpg`. The app detects its version and can install GPG 2.4.8+ if it's missing.
- **Decrypt** files.
- **Encrypt** to keyring recipients or public key files, optionally signing.
- **Sign** — detached, clearsigned or inline.
- **Verify** — good / bad / expired or revoked key / unknown signer, with fingerprint and trust.
- **Keys** — list the keyring and import key files.

Passphrases are passed over stdin, never on the command line. Untrusted recipient keys need an explicit "Trust recipient keys" tick.

### Session
- **History** — what you've run this session, with "Open in Tool" to put an entry's input back. Kept in memory only, cleared when the app closes, and never includes passwords, secrets or keys.

## Prerequisites

- Java 24 or higher
- GPG 2.4.8+ for the GPG tools (the app can install it if missing)

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
- **Jump to a group:** Ctrl/⌘+1 … 6.
- **Use two tools side by side:** "Open in New Window" on any screen; close that window to bring it back.
- **Drop files** onto any input: text boxes load the file (Text Codecs reads binary files as raw bytes; the X.509 input also takes DER, PKCS#12, JKS and CSR files), file-path fields fill in the path.
- **Session → History** (Ctrl/⌘+6) lists what you've run this session, newest first; "Open in Tool" puts an entry's input back. It's kept in memory only, cleared when the app closes, and never includes passwords, secrets or keys.
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
├── ScreenHost.java            # How tool classes hand their screens to the main window
├── TextEnhancements.java      # File drop, right-click menu, hints on every text box
├── CopyFormat.java            # "Copy As" escaping (no Swing)
├── SessionHistory.java        # In-memory history (no Swing); HistoryPanel.java is its screen
├── GPGDecryptor.java          # GPG screens + shared log (GpgPanels.java: Encrypt/Sign/Verify/Keys)
├── GpgVersion.java            # GPG version comparison logic
├── TextCodec.java             # Encoding/decoding/hashing logic (+ ExtraCodecs, FormatDetector, Recipe)
├── EncodingDecodingApp.java   # Text Codecs + Blowfish screens; other Encode/Cipher tabs are *Panel.java
├── CryptoInspectorApp.java    # JWT Verifier + X.509 Inspector (JwtBuilderPanel, KeyGeneratorPanel)
├── gpg/
│   ├── GpgOperations.java        # GPG install/decrypt/encrypt/sign/verify/keys (no Swing)
│   ├── GpgKey.java, GpgVerifyResult.java  # Parsers for gpg's machine-readable output
│   ├── GpgProgressListener.java  # Progress callback interface
│   └── ProcessStarter.java       # Injectable process-starting seam (for tests)
├── crypto/
│   ├── PasswordCipher, BlowfishCodec, BlowfishCbc, Blake2b, HmacGenerator, FileHasher
│   ├── asn1/                     # Small DER reader/writer (CSR parsing, certificate building)
│   ├── jwt/                      # JwtParser, verifiers, JwtSigner, PEM key parsing, JWKS - no Swing
│   └── cert/                     # X509Inspector, ChainValidator, CsrParser, KeyStoreReader,
│                                 # CertificateGenerator, TlsChainFetcher - no Swing
└── util/
    ├── UpdateChecker.java        # GitHub releases API check (no Swing)
    ├── HttpClientFactory.java    # HttpClient w/ Windows trust-store support
    └── NetworkFetchException.java
```

## Dependencies

- [FlatLaf](https://www.formdev.com/flatlaf/) 3.7.2 (+ `flatlaf-intellij-themes`, `flatlaf-extras`) — UI theming
- [SLF4J](https://www.slf4j.org/) 2.0.16 + [Logback](https://logback.qos.ch/) 1.6.1 — logging
- [Jackson Databind](https://github.com/FasterXML/jackson-databind) 2.18.9 — parses the GitHub releases API response, JWT header/payload JSON, and JWKS documents
- No crypto library dependency — the JDK covers HMAC/RSA/EC/Ed25519, AES-GCM, ChaCha20-Poly1305, SHA-3, PBKDF2, certificates and keystores. BLAKE2b and the DER reader/writer used for CSRs and certificate building are small in-repo implementations, tested against RFC vectors, OpenSSL and keytool
- [JUnit Jupiter](https://junit.org/junit5/) 5.10.2 — test scope only
- [Mockito](https://site.mockito.org/) 5.23.0 — test scope only

## License

See LICENSE file for details.
