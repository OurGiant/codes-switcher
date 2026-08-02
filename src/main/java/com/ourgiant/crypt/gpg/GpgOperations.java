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

    public GpgOperations(String gpgPath) {
        this(gpgPath, command -> new ProcessBuilder(command).start());
    }

    GpgOperations(String gpgPath, ProcessStarter processStarter) {
        this.gpgPath = gpgPath;
        this.processStarter = processStarter;
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
