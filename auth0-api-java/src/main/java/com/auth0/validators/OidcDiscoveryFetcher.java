package com.auth0.validators;

import com.auth0.cache.AuthCache;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.models.OidcMetadata;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

/**
 * Fetches and caches OIDC Discovery metadata
 * ({@code .well-known/openid-configuration})
 * from issuer domains.
 * <p>
 * Implements OIDC Discovery with per-domain caching.
 * Uses the unified {@link AuthCache} with the key prefix {@code discovery:}
 * so discovery and JWKS entries coexist in a single cache.
 * </p>
 * <p>
 * Thread-safe: delegates thread safety to the {@link AuthCache} implementation.
 * </p>
 */
class OidcDiscoveryFetcher {

    static final String CACHE_PREFIX = "discovery:";
    private static final String WELL_KNOWN_PATH = ".well-known/openid-configuration";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final AuthCache<Object> cache;
    private final CloseableHttpClient httpClient;

    /**
     * Creates a fetcher with the provided cache and the default HTTP client.
     *
     * @param cache the unified cache instance
     */
    OidcDiscoveryFetcher(AuthCache<Object> cache) {
        this(cache, HttpClients.createDefault());
    }

    /**
     * Creates a fetcher with the provided cache and a custom HTTP client.
     *
     * @param cache      the unified cache instance
     * @param httpClient the HTTP client to use for discovery requests
     */
    OidcDiscoveryFetcher(AuthCache<Object> cache, CloseableHttpClient httpClient) {
        if (cache == null) {
            throw new IllegalArgumentException("cache must not be null");
        }
        if (httpClient == null) {
            throw new IllegalArgumentException("httpClient must not be null");
        }
        this.cache = cache;
        this.httpClient = httpClient;
    }

    /**
     * Fetches the OIDC Discovery metadata for the given issuer, using a cached
     * result if available.
     *
     * @param issuerUrl the token's {@code iss} claim (e.g.,
     *                  {@code "https://tenant.auth0.com/"})
     * @return the parsed {@link OidcMetadata}
     * @throws VerifyAccessTokenException if the fetch or parse fails
     */
    OidcMetadata fetch(String issuerUrl) throws VerifyAccessTokenException {
        String key = CACHE_PREFIX + (issuerUrl.endsWith("/") ? issuerUrl : issuerUrl + "/");

        Object cached = cache.get(key);
        if (cached instanceof OidcMetadata) {
            return (OidcMetadata) cached;
        }

        OidcMetadata metadata = doFetch(issuerUrl.endsWith("/") ? issuerUrl : issuerUrl + "/");
        cache.put(key, metadata);
        return metadata;
    }

    /**
     * Performs the actual HTTP fetch and JSON parsing.
     */
    private OidcMetadata doFetch(String issuerUrl) throws VerifyAccessTokenException {
        String discoveryUrl = issuerUrl + WELL_KNOWN_PATH;

        try {
            HttpGet request = new HttpGet(discoveryUrl);
            request.setHeader("Accept", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    throw new VerifyAccessTokenException(
                            String.format("OIDC discovery failed for issuer '%s': HTTP %d", issuerUrl, statusCode));
                }

                String body = EntityUtils.toString(response.getEntity());
                JsonNode root = OBJECT_MAPPER.readTree(body);

                String issuer = getRequiredField(root, "issuer", issuerUrl);
                String jwksUri = getRequiredField(root, "jwks_uri", issuerUrl);

                return new OidcMetadata(issuer, jwksUri);
            }
        } catch (VerifyAccessTokenException e) {
            throw e;
        } catch (IOException e) {
            throw new VerifyAccessTokenException(
                    String.format("OIDC discovery request failed for issuer '%s'", issuerUrl), e);
        }
    }

    /**
     * Extracts a required string field from the discovery JSON, throwing a clear
     * error if it is missing.
     */
    private String getRequiredField(JsonNode root, String fieldName, String issuerUrl)
            throws VerifyAccessTokenException {
        JsonNode node = root.get(fieldName);
        if (node == null || node.isNull() || !node.isTextual()) {
            throw new VerifyAccessTokenException(
                    String.format("OIDC discovery for issuer '%s' is missing required field '%s'",
                            issuerUrl, fieldName));
        }
        return node.asText();
    }

    /**
     * Clears the entire cache. Primarily for testing.
     */
    void clearCache() {
        cache.clear();
    }

    /**
     * Returns the total number of cached entries (all types). Primarily for
     * testing.
     */
    int cacheSize() {
        return cache.size();
    }

    /**
     * Returns the underlying cache instance. Primarily for testing.
     */
    AuthCache<Object> getCache() {
        return cache;
    }
}
