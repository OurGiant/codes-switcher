package com.ourgiant.crypt.crypto.cert;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Connects to a TLS endpoint and captures the certificate chain the server presents, so it can be
 * handed to {@link X509Inspector} / {@link ChainValidator} for inspection - the same evaluation
 * already applied to a pasted-in chain. Deliberately does NOT rely on the platform trust store: a
 * permissive {@link TrustManager} accepts whatever chain is presented (self-signed, expired,
 * mismatched host, anything) so the handshake always completes and the chain is always captured -
 * the JDK's default trust logic would otherwise throw and hide the chain before this tool ever
 * gets to show it to the user. The actual trust judgement is left to this app's own inspection.
 */
public final class TlsChainFetcher {

    private static final int DEFAULT_TLS_PORT = 443;
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 10_000;

    private TlsChainFetcher() {
    }

    public static final class TlsFetchException extends RuntimeException {
        public TlsFetchException(String message, Throwable cause) {
            super(message, cause);
        }

        public TlsFetchException(String message) {
            super(message);
        }
    }

    public record Endpoint(String host, int port) {
    }

    /** Accepts "host", "host:port", or a URL such as "https://host[:port][/path]". */
    public static Endpoint parseEndpoint(String input) {
        if (input == null || input.isBlank()) {
            throw new TlsFetchException("No host or URL provided");
        }
        String trimmed = input.trim();

        if (trimmed.contains("://")) {
            URI uri;
            try {
                uri = new URI(trimmed);
            } catch (URISyntaxException e) {
                throw new TlsFetchException("Invalid URL: " + e.getMessage(), e);
            }
            String host = uri.getHost();
            if (host == null) {
                throw new TlsFetchException("Could not determine host from \"" + trimmed + "\"");
            }
            return new Endpoint(host, uri.getPort() == -1 ? DEFAULT_TLS_PORT : uri.getPort());
        }

        int colon = trimmed.indexOf(':');
        if (colon > 0 && colon == trimmed.lastIndexOf(':') && colon < trimmed.length() - 1) {
            String host = trimmed.substring(0, colon);
            String portText = trimmed.substring(colon + 1);
            try {
                return new Endpoint(host, Integer.parseInt(portText));
            } catch (NumberFormatException e) {
                throw new TlsFetchException("Invalid port in \"" + trimmed + "\"");
            }
        }

        return new Endpoint(trimmed, DEFAULT_TLS_PORT);
    }

    /** Parses a host/host:port/URL and connects, returning the leaf-first chain the server presented. */
    public static List<X509Certificate> fetchChain(String hostOrUrl) {
        Endpoint endpoint = parseEndpoint(hostOrUrl);
        return fetchChain(endpoint.host(), endpoint.port());
    }

    public static List<X509Certificate> fetchChain(String host, int port) {
        AtomicReference<X509Certificate[]> captured = new AtomicReference<>();

        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[0], new TrustManager[]{capturingTrustManager(captured)}, null);
            SSLSocketFactory factory = context.getSocketFactory();

            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
                socket.setSoTimeout(READ_TIMEOUT_MS);

                SSLParameters params = socket.getSSLParameters();
                params.setServerNames(List.of(new SNIHostName(host)));
                socket.setSSLParameters(params);

                socket.startHandshake();
            }
        } catch (IOException e) {
            throw new TlsFetchException("Could not connect to " + host + ":" + port + " - " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new TlsFetchException("TLS setup failed: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            // SNIHostName rejects e.g. bare IP-literal hosts - fetch still works, SNI just doesn't apply.
            throw new TlsFetchException("Invalid host \"" + host + "\": " + e.getMessage(), e);
        }

        X509Certificate[] chain = captured.get();
        if (chain == null || chain.length == 0) {
            throw new TlsFetchException("Server presented no certificate chain");
        }
        return List.of(chain);
    }

    private static X509ExtendedTrustManager capturingTrustManager(AtomicReference<X509Certificate[]> captured) {
        return new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                captured.set(chain);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
                captured.set(chain);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
                captured.set(chain);
            }
        };
    }
}
