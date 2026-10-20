package com.ourgiant.crypt.gpg;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * GPG install/decrypt operations, kept free of javax.swing so they're
 * testable without a display. GUI code drives this through a
 * {@link GpgProgressListener} rather than this class touching Swing directly.
 */
public class GpgOperations {

    public static final String BUILD_DIR_PROPERTY = "codes.switcher.gpgBuildDir";

    private static final Logger log = LoggerFactory.getLogger(GpgOperations.class);

    private final String gpgPath;
    private final ProcessStarter processStarter;
    private final Path homeDir; // null = gpg's default keyring

    public GpgOperations(String gpgPath) {
        this(gpgPath, command -> new ProcessBuilder(command).start());
    }

    GpgOperations(String gpgPath, ProcessStarter processStarter) {
        this(gpgPath, processStarter, null);
    }

    /** {@code homeDir} points gpg at a separate keyring; tests use it to stay out of the real one. */
    GpgOperations(String gpgPath, ProcessStarter processStarter, Path homeDir) {
        this.gpgPath = gpgPath;
        this.processStarter = processStarter;
        this.homeDir = homeDir;
    }

    /** How a file is signed. */
    public enum SignMode {
        /** Separate .sig/.asc file; the original file is untouched. */
        DETACHED,
        /** Readable text with the signature wrapped around it (text files only). */
        CLEARSIGN,
        /** Signature and data in one binary (or armored) file. */
        INLINE
    }

    /** Captured output of one gpg run. */
    record Result(int exitCode, String stdout, String stderr) {
    }

    public String checkGpgVersion() {
        try {
            Process process = processStarter.start(List.of(gpgPath, "--version"));
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                process.waitFor();
                return line != null ? line : "Unknown";
            }
        } catch (Exception e) {
            log.debug("GPG version check failed", e);
            return "GPG not found";
        }
    }

    public boolean decryptFile(String encryptedFile, String keyFile, String outputFile,
                                String passphrase, GpgProgressListener listener) {
        try {
            listener.onMessage("Starting decryption process...");

            if (keyFile != null && !keyFile.isEmpty()) {
                listener.onMessage("Importing key from: " + keyFile);
                Process importProcess = processStarter.start(List.of(gpgPath, "--import", keyFile));
                try (BufferedReader importReader =
                             new BufferedReader(new InputStreamReader(importProcess.getErrorStream()))) {
                    String line;
                    while ((line = importReader.readLine()) != null) {
                        listener.onMessage("  " + line);
                    }
                }
                importProcess.waitFor();
            }

            List<String> command = (passphrase == null || passphrase.isEmpty())
                    ? List.of(gpgPath, "--decrypt", "--output", outputFile, encryptedFile)
                    : List.of(gpgPath, "--batch", "--yes", "--passphrase-fd", "0",
                              "--decrypt", "--output", outputFile, encryptedFile);

            listener.onMessage("Executing: " + String.join(" ", command));
            Process process = processStarter.start(command);

            if (passphrase != null && !passphrase.isEmpty()) {
                try (OutputStream os = process.getOutputStream()) {
                    os.write((passphrase + "\n").getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }
            }

            try (BufferedReader errorReader =
                         new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = errorReader.readLine()) != null) {
                    listener.onMessage(line);
                }
            }

            int exitCode = process.waitFor();

            if (exitCode == 0 && Files.exists(Paths.get(outputFile))) {
                listener.onMessage("SUCCESS: File decrypted successfully!");
                listener.onMessage("Output saved to: " + outputFile);
                return true;
            } else {
                listener.onMessage("ERROR: Decryption failed with exit code " + exitCode);
                return false;
            }
        } catch (Exception e) {
            listener.onMessage("ERROR: " + e.getMessage());
            log.error("Decryption failed", e);
            return false;
        }
    }

    // ------------------------------------------------------------------ keys

    /** Lists public keys, or secret keys when {@code secret} is true. */
    public java.util.List<GpgKey> listKeys(boolean secret) throws IOException {
        Result r = run(command("--with-colons", "--fixed-list-mode", "--with-fingerprint",
                secret ? "--list-secret-keys" : "--list-keys"), null);
        if (r.exitCode() != 0 && r.stdout().isBlank()) {
            // An empty keyring exits 2 on some versions; only fail if gpg printed an error and nothing else.
            if (r.stderr().toLowerCase().contains("error")) {
                throw new IOException("gpg --list-keys failed: " + r.stderr().strip());
            }
        }
        return GpgKey.parseColons(r.stdout());
    }

    /** Imports keys from a file (public or secret). */
    public boolean importKeys(String keyFile, GpgProgressListener listener) {
        try {
            Result r = run(command("--import", keyFile), null);
            r.stderr().lines().forEach(l -> listener.onMessage("  " + l));
            return r.exitCode() == 0;
        } catch (IOException e) {
            listener.onMessage("ERROR: " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------ encrypt / sign / verify

    /**
     * Encrypts {@code inputFile} to the given recipients (key IDs, fingerprints or emails in the keyring)
     * and/or public key files, optionally signing with {@code signerKey}.
     *
     * @param trustRecipients pass {@code --trust-model always}; without it gpg refuses keys it hasn't been told to trust
     */
    public boolean encryptFile(String inputFile, String outputFile, java.util.List<String> recipients,
                               java.util.List<String> recipientFiles, boolean armor, boolean trustRecipients,
                               String signerKey, String passphrase, GpgProgressListener listener) {
        if (recipients.isEmpty() && recipientFiles.isEmpty()) {
            listener.onMessage("ERROR: Choose at least one recipient key or key file.");
            return false;
        }
        java.util.List<String> args = new java.util.ArrayList<>(java.util.List.of("--batch", "--yes"));
        if (armor) {
            args.add("--armor");
        }
        if (trustRecipients) {
            args.addAll(java.util.List.of("--trust-model", "always"));
        }
        for (String r : recipients) {
            args.addAll(java.util.List.of("--recipient", r));
        }
        for (String f : recipientFiles) {
            args.addAll(java.util.List.of("--recipient-file", f));
        }
        boolean sign = signerKey != null && !signerKey.isBlank();
        if (sign) {
            addPassphraseArgs(args, passphrase);
            args.addAll(java.util.List.of("--local-user", signerKey, "--sign"));
        }
        args.addAll(java.util.List.of("--output", outputFile, "--encrypt", inputFile));
        return runToFile("Encrypting", args, sign ? passphrase : null, outputFile, listener, true);
    }

    /** Signs {@code inputFile}. {@code signerKey} may be blank to use gpg's default key. */
    public boolean signFile(String inputFile, String outputFile, SignMode mode, boolean armor,
                            String signerKey, String passphrase, GpgProgressListener listener) {
        java.util.List<String> args = new java.util.ArrayList<>(java.util.List.of("--batch", "--yes"));
        addPassphraseArgs(args, passphrase);
        if (signerKey != null && !signerKey.isBlank()) {
            args.addAll(java.util.List.of("--local-user", signerKey));
        }
        if (armor && mode != SignMode.CLEARSIGN) {
            args.add("--armor");
        }
        args.addAll(java.util.List.of("--output", outputFile));
        args.add(switch (mode) {
            case DETACHED -> "--detach-sign";
            case CLEARSIGN -> "--clearsign";
            case INLINE -> "--sign";
        });
        args.add(inputFile);
        return runToFile("Signing", args, passphrase, outputFile, listener, false);
    }

    /**
     * Verifies a signature. For a detached signature pass the data file too; for clearsigned or
     * inline-signed files pass {@code dataFile = null}.
     */
    public GpgVerifyResult verifySignature(String signatureFile, String dataFile, GpgProgressListener listener) {
        java.util.List<String> args = new java.util.ArrayList<>(java.util.List.of("--batch", "--status-fd", "1", "--verify", signatureFile));
        if (dataFile != null && !dataFile.isBlank()) {
            args.add(dataFile);
        }
        try {
            Result r = run(command(args.toArray(String[]::new)), null);
            r.stderr().lines().forEach(listener::onMessage);
            return GpgVerifyResult.parseStatus(r.stdout());
        } catch (IOException e) {
            listener.onMessage("ERROR: " + e.getMessage());
            return new GpgVerifyResult(GpgVerifyResult.Status.ERROR, null, null, null, null, null, e.getMessage());
        }
    }

    private static void addPassphraseArgs(java.util.List<String> args, String passphrase) {
        if (passphrase != null && !passphrase.isEmpty()) {
            args.addAll(java.util.List.of("--pinentry-mode", "loopback", "--passphrase-fd", "0"));
        }
    }

    private boolean runToFile(String verb, java.util.List<String> args, String passphrase, String outputFile,
                              GpgProgressListener listener, boolean hintTrust) {
        try {
            java.util.List<String> cmd = command(args.toArray(String[]::new));
            listener.onMessage(verb + ": " + String.join(" ", cmd));
            Result r = run(cmd, passphrase);
            r.stderr().lines().forEach(listener::onMessage);
            if (r.exitCode() == 0 && Files.exists(Paths.get(outputFile))) {
                listener.onMessage("SUCCESS: Output saved to " + outputFile);
                return true;
            }
            listener.onMessage("ERROR: " + verb + " failed with exit code " + r.exitCode());
            String err = r.stderr().toLowerCase();
            if (hintTrust && (err.contains("no assurance") || err.contains("unusable public key")
                    || err.contains("not trusted"))) {
                listener.onMessage("HINT: gpg doesn't trust that recipient key yet. Tick \"Trust recipient keys\" "
                        + "if you've checked the key's fingerprint with its owner.");
            }
            if (err.contains("bad passphrase")) {
                listener.onMessage("HINT: The passphrase for the signing key is wrong.");
            }
            return false;
        } catch (IOException e) {
            listener.onMessage("ERROR: " + e.getMessage());
            log.error("{} failed", verb, e);
            return false;
        }
    }

    /** gpg, plus {@code --homedir} when one is configured, plus {@code args}. */
    java.util.List<String> command(String... args) {
        java.util.List<String> cmd = new java.util.ArrayList<>();
        cmd.add(gpgPath);
        if (homeDir != null) {
            cmd.addAll(java.util.List.of("--homedir", homeDir.toString()));
        }
        cmd.addAll(java.util.List.of(args));
        return cmd;
    }

    /** Runs gpg, feeding {@code stdin} (may be null) and reading stdout and stderr concurrently. */
    Result run(java.util.List<String> command, String stdin) throws IOException {
        Process process = processStarter.start(command);
        java.util.concurrent.CompletableFuture<String> err = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                return new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                return "";
            }
        });
        try (OutputStream os = process.getOutputStream()) {
            if (stdin != null) {
                os.write((stdin + "\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ignored) {
            // gpg may exit before reading stdin; its exit code tells us what happened
        }
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        try {
            int code = process.waitFor();
            return new Result(code, out, err.join());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroy();
            throw new IOException("Interrupted while waiting for gpg", e);
        }
    }

    public Path prepareBuildDirectory() throws IOException {
        Path dir = buildDirectory();
        Files.createDirectories(dir);
        return dir;
    }

    private Path buildDirectory() {
        String override = System.getProperty(BUILD_DIR_PROPERTY);
        if (override != null && !override.isBlank()) {
            return Paths.get(override);
        }
        return Paths.get(System.getProperty("user.home"), "gpg-build");
    }
}
