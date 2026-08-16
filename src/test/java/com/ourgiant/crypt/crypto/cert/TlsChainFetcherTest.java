package com.ourgiant.crypt.crypto.cert;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsChainFetcherTest {

    @Test
    void fetchesTheChainPresentedByARealTlsServer(@TempDir Path tempDir) throws Exception {
        KeyStore keyStore = CertFixtures.selfSignedKeyStore(tempDir, "server", "CN=localhost", "RSA", "2048", 365);
        X509Certificate serverCert = (X509Certificate) keyStore.getCertificate("server");

        try (SSLServerSocket serverSocket = startServer(keyStore)) {
            int port = serverSocket.getLocalPort();
            Thread serverThread = acceptOnce(serverSocket);

            List<X509Certificate> chain = TlsChainFetcher.fetchChain("localhost", port);

            assertEquals(1, chain.size());
            assertEquals(serverCert, chain.get(0));
            serverThread.join(5_000);
        }
    }

    @Test
    void parsesUrlHostAndUrlWithExplicitPort() {
        var withoutPort = TlsChainFetcher.parseEndpoint("https://example.com/path");
        assertEquals("example.com", withoutPort.host());
        assertEquals(443, withoutPort.port());

        var withPort = TlsChainFetcher.parseEndpoint("https://example.com:8443/path");
        assertEquals("example.com", withPort.host());
        assertEquals(8443, withPort.port());
    }

    @Test
    void parsesBareHostAndHostWithPort() {
        var bareHost = TlsChainFetcher.parseEndpoint("example.com");
        assertEquals("example.com", bareHost.host());
        assertEquals(443, bareHost.port());

        var hostPort = TlsChainFetcher.parseEndpoint("example.com:8443");
        assertEquals("example.com", hostPort.host());
        assertEquals(8443, hostPort.port());
    }

    @Test
    void rejectsBlankInput() {
        assertThrows(TlsChainFetcher.TlsFetchException.class, () -> TlsChainFetcher.parseEndpoint("  "));
    }

    @Test
    void rejectsInvalidPort() {
        assertThrows(TlsChainFetcher.TlsFetchException.class, () -> TlsChainFetcher.parseEndpoint("example.com:notaport"));
    }

    @Test
    void wrapsConnectionFailureInFetchException() {
        // Port 1 is a privileged, essentially-never-listening port - connection should be refused.
        TlsChainFetcher.TlsFetchException ex = assertThrows(TlsChainFetcher.TlsFetchException.class,
            () -> TlsChainFetcher.fetchChain("127.0.0.1", 1));
        assertTrue(ex.getMessage().contains("127.0.0.1"));
    }

    private static SSLServerSocket startServer(KeyStore keyStore) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);
        SSLServerSocketFactory ssf = serverContext.getServerSocketFactory();
        return (SSLServerSocket) ssf.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }

    private static Thread acceptOnce(SSLServerSocket serverSocket) {
        Thread thread = new Thread(() -> {
            try (Socket client = serverSocket.accept()) {
                ((SSLSocket) client).startHandshake();
            } catch (IOException ignored) {
                // Client side closes right after the handshake completes; a reset here is expected.
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }
}
