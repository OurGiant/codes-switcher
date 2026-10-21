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

### Classic Ciphers
For puzzles, CTFs and learning, not for protecting real secrets.
- **Enigma** — an Enigma I / M3 simulator, a nod to *The Imitation Game*: rotors I–VIII, reflector B or C, ring settings, start positions and up to 13 plugboard pairs, with the middle rotor's double step. The same settings encrypt and decrypt. Keeps or drops spaces and punctuation, can group output in fives, and shows the rotor windows after the last key press. "Load Example" fills in a real 1941 message.
- **Book Cipher** — an Ottendorf cipher, a nod to *National Treasure*: any pasted or loaded text is the book. Words become `line-word` codes, or letters become `line-word-letter`; each encoding picks a random place, so repeated words get different codes. Case and punctuation around words are ignored.
- **Substitution** — Atbash, Caesar (any shift, or "Try All 26" ranked by how English each result looks) and Vigenère with a keyword. Case, spaces and punctuation stay in place.
- **Vigenère Cracker** — a nod to *The Da Vinci Code*: finds the key length (index of coincidence, with Kasiski repeats as a check), recovers each key letter by chi-square against English letter frequencies, and lists the best keys with a preview. Works best with a few hundred letters of English.

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

### Steganography
- **Hide Message** — hide text or a file inside an image (PNG, BMP, JPEG or GIF in; **PNG out**). It's encrypted with AES-256-GCM from your password, then written into the lowest bit of the image's colour values at password-scattered positions, so each colour changes by at most 1/255. A meter shows how much fits (an 800×500 image holds about 146 KB).
- **Reveal Message** — get the text or file back with the password. A wrong password and a clean image look the same ("nothing found"); an image that was edited or recompressed after hiding is reported as damaged.
- **Analyze Image** — view the image's lowest-bit plane and run a chi-square test for LSB hiding, e.g. for CTF puzzles.

Keep the PNG exactly as saved: converting it to JPEG, editing it, or sending it through apps that compress images erases the message. The encryption protects what you hid, but the method can be detected by specialised analysis, so it hides content, not the fact that something is hidden.

There's also a hidden way to use three images as the key; see [Easter eggs](#easter-eggs).

### Session
- **History** — what you've run this session, with "Open in Tool" to put an entry's input back. Kept in memory only, cleared when the app closes, and never includes passwords, secrets or keys.

## Easter eggs

A few hidden extras, each a nod to a film. Type the code word in the tool search (Ctrl/⌘+K) and press Enter; typing it again switches it off. They last only for the current session.

<details>
<summary>Spoilers</summary>

- `mnemonic`, **Courier Mode** (*Johnny Mnemonic*, 1995):
  - Hide Message and Reveal Message can use **three images** as the key instead of a password, in any order.
  - The key is built from the images' pixels, so lossless re-saves (PNG to BMP) keep it, while edits or JPEG recompression change it.
  - Anyone with the same three files can reveal the message, so keep them as private as a password.
  - The mode isn't saved between sessions, so switch it on again to reveal a message hidden this way.
  - The app goes neon green while it's on.
- `setec astronomy` (*Sneakers*, 1992): decrypted and decoded output resolves letter by letter. Only the drawing is scrambled; the text itself, Copy and History always have the exact output, and any click or key press ends it.
- `joshua` (*WarGames*, 1983): a terminal-style **password strength checker**.
  - It gives an estimate of how many guesses a password would take, based on common passwords, words, look-alike swaps, repeats, sequences, keyboard runs and years.
  - It shows average crack times for four kinds of attack.
  - Nothing typed there is saved, logged or sent anywhere.
- Three wrong passwords in a row (*Jurassic Park*, 1993): a small notice that you didn't say the magic word. It appears once per session and closes itself.
- `white rabbit` (*The Matrix*, 1999): progress bars run on digital rain.
- `hack the planet` (*Hackers*, 1995): a loud magenta-and-cyan theme. It and Courier Mode switch each other off.
- `macrodata refinement` (also `mdr` or `lumon`) (*Severance*): a retro terminal of drifting numbers. Find the scary ones (they twitch as the cursor nears), click a group, then sort it into one of five bins until the file is 100% complete.
</details>

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

One window opens with every tool in a sidebar, grouped as Encode / Decode, Ciphers, Classic Ciphers,
JWT, Certificates, GPG, Steganography and Session. It reopens on the screen, size and position you last used.

- **Find a tool:** Ctrl+K (⌘K on macOS), type, press Enter.
- **Jump to a group:** Ctrl/⌘+1 … 8.
- **Use two tools side by side:** "Open in New Window" on any screen; close that window to bring it back.
- **Drop files** onto any input: text boxes load the file (Text Codecs reads binary files as raw bytes; the X.509 input also takes DER, PKCS#12, JKS and CSR files), file-path fields fill in the path.
- **Session → History** (Ctrl/⌘+8) lists what you've run this session, newest first; "Open in Tool" puts an entry's input back. It's kept in memory only, cleared when the app closes, and never includes passwords, secrets or keys.
- **Right-click any text box** for Cut / Copy / Paste and **Copy As** plain text, JSON/JavaScript, Java or Python string, or a Markdown code block.

To start on a particular screen, pass `--tool`:

```bash
java -jar target/decrypter-all.jar --tool=gpg      # also: jwt, jwt-builder, x509, keygen, hash, recipe, hmac, aes, blowfish, enigma, caesar …
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
├── StegoPanels.java           # Hide / Reveal / Analyze screens
├── ClassicCipherPanels.java   # Enigma / Book Cipher / Substitution / Vigenère Cracker screens
├── EasterEggs.java            # Code words; CourierMode, TextReveal, WoprDialog, MagicWord, MatrixProgressBarUI, Macrodata*
├── crypto/
│   ├── PasswordCipher, BlowfishCodec, BlowfishCbc, Blake2b, HmacGenerator, FileHasher, PasswordStrength
│   ├── classic/                  # Enigma, BookCipher, ClassicCiphers, VigenereCracker - no Swing
│   ├── stego/                    # Steganography (hide/reveal), StegoAnalysis, CourierKey - no Swing
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
