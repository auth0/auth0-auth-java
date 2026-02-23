package com.auth0.spring.boot;

import java.util.Collections;
import java.util.Map;

/**
 * Immutable request context passed to {@link Auth0DomainResolver} for dynamic
 * domain resolution in Multi-Custom Domain (MCD) scenarios.
 * <p>
 * Contains all the information a resolver needs to determine which issuer
 * domains are valid for the incoming request:
 * <ul>
 * <li>{@code url} — the URL the API request was made to</li>
 * <li>{@code headers} — relevant HTTP request headers (lowercase keys)</li>
 * <li>{@code tokenIssuer} — the <b>unverified</b> {@code iss} claim from the
 * JWT</li>
 * </ul>
 *
 * <p>
 * <b>Warning:</b> The {@code tokenIssuer} has NOT been verified yet. It is
 * provided as a routing hint only and must not be trusted on its own.
 * </p>
 *
 * @see Auth0DomainResolver
 */
public final class Auth0RequestContext {

    private final String url;
    private final Map<String, String> headers;
    private final String tokenIssuer;

    /**
     * Creates a new request context.
     *
     * @param url         the request URL
     * @param headers     the request headers (will be wrapped as unmodifiable)
     * @param tokenIssuer the unverified {@code iss} claim from the JWT
     */
    public Auth0RequestContext(String url, Map<String, String> headers, String tokenIssuer) {
        this.url = url;
        this.headers = headers != null
                ? Collections.unmodifiableMap(headers)
                : Collections.emptyMap();
        this.tokenIssuer = tokenIssuer;
    }

    /**
     * Returns the URL the API request was made to.
     *
     * @return the request URL, or {@code null} if not available
     */
    public String getUrl() {
        return url;
    }

    /**
     * Returns an unmodifiable map of request headers (lowercase keys).
     *
     * @return the request headers; never {@code null}
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * Returns the unverified {@code iss} claim from the incoming JWT.
     * <p>
     * <b>Warning:</b> This value has NOT been verified. Use it only as a
     * routing hint (e.g., to look up tenant configuration).
     *
     * @return the unverified issuer, or {@code null} if not available
     */
    public String getTokenIssuer() {
        return tokenIssuer;
    }
}
