package com.ourgiant.crypt.gpg;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GpgOperationsTest {

    @Mock
    private Process process;

    private String originalBuildDirProperty;

    @BeforeEach
    void saveBuildDirProperty() {
        originalBuildDirProperty = System.getProperty(GpgOperations.BUILD_DIR_PROPERTY);
    }

    @AfterEach
    void restoreBuildDirProperty() {
        if (originalBuildDirProperty == null) {
            System.clearProperty(GpgOperations.BUILD_DIR_PROPERTY);
        } else {
            System.setProperty(GpgOperations.BUILD_DIR_PROPERTY, originalBuildDirProperty);
        }
    }

    private static InputStream streamOf(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void checkGpgVersionReturnsFirstLineOfVersionOutput() throws Exception {
        when(process.getInputStream()).thenReturn(streamOf("gpg (GnuPG) 2.4.8\nlibgcrypt 1.10.3\n"));
        when(process.waitFor()).thenReturn(0);

        GpgOperations ops = new GpgOperations("gpg", command -> process);

        assertEquals("gpg (GnuPG) 2.4.8", ops.checkGpgVersion());
    }

    @Test
    void checkGpgVersionReturnsNotFoundWhenProcessStartFails() {
        GpgOperations ops = new GpgOperations("gpg", command -> {
            throw new IOException("no such file");
        });

        assertEquals("GPG not found", ops.checkGpgVersion());
    }

    @Test
    void decryptFileReturnsTrueAndReportsSuccessWhenExitCodeZeroAndOutputExists(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("decrypted.txt");
        Files.writeString(outputFile, "plaintext"); // simulates gpg having written the output

        when(process.getErrorStream()).thenReturn(streamOf(""));
        when(process.waitFor()).thenReturn(0);

        GpgOperations ops = new GpgOperations("gpg", command -> process);
        List<String> messages = new ArrayList<>();

        boolean result = ops.decryptFile("in.gpg", "", outputFile.toString(), "", messages::add);

        assertTrue(result);
        assertTrue(messages.stream().anyMatch(m -> m.contains("SUCCESS")));
    }

    @Test
    void decryptFileReturnsFalseAndReportsErrorWhenExitCodeNonZero(@TempDir Path tempDir) throws Exception {
        when(process.getErrorStream()).thenReturn(streamOf("gpg: decryption failed: Bad session key"));
        when(process.waitFor()).thenReturn(2);

        GpgOperations ops = new GpgOperations("gpg", command -> process);
        List<String> messages = new ArrayList<>();

        boolean result = ops.decryptFile("in.gpg", "", tempDir.resolve("out.txt").toString(), "", messages::add);

        assertFalse(result);
        assertTrue(messages.stream().anyMatch(m -> m.contains("ERROR")));
    }

    @Test
    void decryptFileImportsKeyBeforeDecrypting(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("decrypted.txt");
        Files.writeString(outputFile, "plaintext");

        Process importProcess = mock(Process.class);
        when(importProcess.getErrorStream()).thenReturn(streamOf(""));

        when(process.getErrorStream()).thenReturn(streamOf(""));
        when(process.waitFor()).thenReturn(0);

        List<List<String>> commandsStarted = new ArrayList<>();
        ProcessStarter starter = command -> {
            commandsStarted.add(command);
            return commandsStarted.size() == 1 ? importProcess : process;
        };

        GpgOperations ops = new GpgOperations("gpg", starter);
        boolean result = ops.decryptFile("in.gpg", "key.asc", outputFile.toString(), "", msg -> { });

        assertTrue(result);
        assertEquals(2, commandsStarted.size());
        assertEquals(List.of("gpg", "--import", "key.asc"), commandsStarted.get(0));
        assertTrue(commandsStarted.get(1).contains("--decrypt"));
    }

    @Test
    void decryptFileOmitsPassphraseFlagsWhenPassphraseEmpty(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("decrypted.txt");
        Files.writeString(outputFile, "plaintext");

        when(process.getErrorStream()).thenReturn(streamOf(""));
        when(process.waitFor()).thenReturn(0);

        ProcessStarter starter = mock(ProcessStarter.class);
        when(starter.start(any())).thenReturn(process);

        GpgOperations ops = new GpgOperations("gpg", starter);
        ops.decryptFile("in.gpg", "", outputFile.toString(), "", msg -> { });

        ArgumentCaptor<List<String>> captor = ArgumentCaptor.forClass(List.class);
        verify(starter).start(captor.capture());
        assertFalse(captor.getValue().contains("--passphrase-fd"));
        assertFalse(captor.getValue().contains("--batch"));
    }

    @Test
    void decryptFileWritesPassphraseToProcessStdinWhenProvided(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("decrypted.txt");
        Files.writeString(outputFile, "plaintext");

        ByteArrayOutputStream stdin = new ByteArrayOutputStream();
        when(process.getErrorStream()).thenReturn(streamOf(""));
        when(process.getOutputStream()).thenReturn(stdin);
        when(process.waitFor()).thenReturn(0);

        GpgOperations ops = new GpgOperations("gpg", command -> process);
        ops.decryptFile("in.gpg", "", outputFile.toString(), "s3cret", msg -> { });

        assertEquals("s3cret\n", stdin.toString(StandardCharsets.UTF_8));
    }

    @Test
    void prepareBuildDirectoryUsesSystemPropertyOverride(@TempDir Path tempDir) throws Exception {
        Path overrideDir = tempDir.resolve("custom-gpg-build");
        System.setProperty(GpgOperations.BUILD_DIR_PROPERTY, overrideDir.toString());

        GpgOperations ops = new GpgOperations("gpg");
        Path result = ops.prepareBuildDirectory();

        assertEquals(overrideDir, result);
        assertTrue(Files.isDirectory(overrideDir));
    }

    @Test
    void prepareBuildDirectoryFallsBackToUserHomeWhenPropertyNotSet(@TempDir Path tempDir) throws Exception {
        System.clearProperty(GpgOperations.BUILD_DIR_PROPERTY);
        String originalUserHome = System.getProperty("user.home");
        System.setProperty("user.home", tempDir.toString());
        try {
            GpgOperations ops = new GpgOperations("gpg");
            Path result = ops.prepareBuildDirectory();

            assertEquals(tempDir.resolve("gpg-build"), result);
            assertTrue(Files.isDirectory(tempDir.resolve("gpg-build")));
        } finally {
            System.setProperty("user.home", originalUserHome);
        }
    }
}
