package com.ourgiant.crypt.crypto.jwt;

import com.ourgiant.crypt.util.HttpClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Fetches a JWKS document from a user-supplied {@code jwks_uri}. Unlike AboutDialog's release-URL
 * check, there's no host allowlisting here - the user is the one typing this URL deliberately
 * (the same trust model as pasting a URL into a browser), not an untrusted API response feeding
 * in an attacker-chosen destination.
 */
public final class JwksFetcher {
    private static final Logger log = LoggerFactory.getLogger(JwksFetcher.class);
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private JwksFetcher() {
    }

    public static String fetch(String jwksUrl) {
        try {
            HttpClient client = HttpClientFactory.create(CONNECT_TIMEOUT);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(jwksUrl))
                .header("Accept", "application/json")
                .timeout(REQUEST_TIMEOUT)
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new JwksKeys.JwksException(
                    "JWKS endpoint returned HTTP " + response.statusCode());
            }
            return response.body();
        } catch (JwksKeys.JwksException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Failed to fetch JWKS from {}", jwksUrl, e);
            throw new JwksKeys.JwksException("Failed to fetch JWKS: " + e.getMessage(), e);
        }
    }
}
