package com.auth0.models;

import java.util.Collections;
import java.util.Map;

/**
 * Contextual information about the incoming API request, provided to the domain resolver.
 */
public class RequestContext {

    private final String url;
    private final Map<String, String> headers;
    private final String tokenIssuer;

    private RequestContext(Builder builder) {
        this.url = builder.url;
        this.headers = builder.headers != null
                ? Collections.unmodifiableMap(builder.headers)
                : Collections.emptyMap();
        this.tokenIssuer = builder.tokenIssuer;
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
     * Returns an unmodifiable map of relevant request headers.
     *
     * @return the request headers; never {@code null}
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * Returns the unverified {@code iss} claim from the incoming JWT.
     *
     * @return the unverified token issuer, or {@code null} if not available
     */
    public String getTokenIssuer() {
        return tokenIssuer;
    }

    /**
     * Builder for {@link RequestContext}.
     */
    public static class Builder {
        private String url;
        private Map<String, String> headers;
        private String tokenIssuer;

        /**
         * Sets the URL the API request was made to.
         *
         * @param url the request URL
         * @return this builder
         */
        public Builder url(String url) {
            this.url = url;
            return this;
        }

        /**
         * Sets the relevant request headers.
         *
         * @param headers a map of header names to values
         * @return this builder
         */
        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        /**
         * Sets the unverified {@code iss} claim from the token.
         *
         * @param tokenIssuer the unverified issuer claim
         * @return this builder
         */
        public Builder tokenIssuer(String tokenIssuer) {
            this.tokenIssuer = tokenIssuer;
            return this;
        }

        /**
         * Builds an immutable {@link RequestContext}.
         *
         * @return the request context
         */
        public RequestContext build() {
            return new RequestContext(this);
        }
    }
}
