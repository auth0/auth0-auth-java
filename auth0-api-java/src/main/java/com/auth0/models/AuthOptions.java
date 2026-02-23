package com.auth0.models;

import com.auth0.DomainResolver;
import com.auth0.cache.AuthCache;
import com.auth0.enums.DPoPMode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AuthOptions {
    private final String domain;
    private final List<String> domains;
    private final DomainResolver domainsResolver;
    private final String audience;
    private final DPoPMode dpopMode;

    private final long dpopIatOffsetSeconds;
    private final long dpopIatLeewaySeconds;

    private final int cacheMaxEntries;
    private final long cacheTtlSeconds;
    private final AuthCache<Object> cache;

    public AuthOptions(Builder builder) {
        this.domain = builder.domain;
        this.domains = builder.domains != null
                ? Collections.unmodifiableList(new ArrayList<>(builder.domains))
                : null;
        this.domainsResolver = builder.domainsResolver;
        this.audience = builder.audience;
        this.dpopMode = builder.dpopMode;

        this.dpopIatOffsetSeconds = builder.dpopIatOffsetSeconds;
        this.dpopIatLeewaySeconds = builder.dpopIatLeewaySeconds;

        this.cacheMaxEntries = builder.cacheMaxEntries;
        this.cacheTtlSeconds = builder.cacheTtlSeconds;
        this.cache = builder.cache;
    }

    public String getDomain() {
        return domain;
    }

    /**
     * Returns the static list of allowed issuer domains, or {@code null} if not
     * configured.
     *
     * @return unmodifiable list of domain strings, or {@code null}
     */
    public List<String> getDomains() {
        return domains;
    }

    /**
     * Returns the dynamic domain resolver, or {@code null} if not configured.
     *
     * @return the {@link DomainResolver}, or {@code null}
     */
    public DomainResolver getDomainsResolver() {
        return domainsResolver;
    }

    public String getAudience() {
        return audience;
    }

    public DPoPMode getDpopMode() {
        return dpopMode;
    }

    public long getDpopIatOffsetSeconds() {
        return dpopIatOffsetSeconds;
    }

    public long getDpopIatLeewaySeconds() {
        return dpopIatLeewaySeconds;
    }

    /**
     * Returns the maximum number of entries for the in-memory cache.
     * Applies when no custom {@link AuthCache} is provided.
     *
     * @return the max entries limit (default 100)
     */
    public int getCacheMaxEntries() {
        return cacheMaxEntries;
    }

    /**
     * Returns the TTL in seconds for cached entries.
     * Applies when no custom {@link AuthCache} is provided.
     *
     * @return the TTL in seconds (default 600 = 10 minutes)
     */
    public long getCacheTtlSeconds() {
        return cacheTtlSeconds;
    }

    /**
     * Returns the custom cache implementation, or {@code null} if the default
     * in-memory cache should be used.
     * <p>
     * The unified cache stores both OIDC discovery metadata and JWKS providers
     * using key prefixes ({@code discovery:} and {@code jwks:}).
     * </p>
     *
     * @return the custom cache, or {@code null}
     */
    public AuthCache<Object> getCache() {
        return cache;
    }

    public static class Builder {
        private String domain;
        private List<String> domains;
        private DomainResolver domainsResolver;
        private String audience;
        private DPoPMode dpopMode = DPoPMode.ALLOWED;

        private long dpopIatOffsetSeconds = 300;
        private long dpopIatLeewaySeconds = 30;

        private int cacheMaxEntries = 100;
        private long cacheTtlSeconds = 600;
        private AuthCache<Object> cache;

        public Builder domain(String domain) {
            this.domain = domain;
            return this;
        }

        /**
         * Sets a static list of allowed issuer domains for multi-custom-domain support.
         * <p>
         * Cannot be used together with {@link #domainsResolver(DomainResolver)}.
         * Can coexist with {@link #domain(String)} for Auth for Agents scenarios,
         * in which case this list takes precedence for token validation.
         * </p>
         *
         * @param domains list of allowed issuer domain strings
         * @return this builder
         */
        public Builder domains(List<String> domains) {
            this.domains = domains;
            return this;
        }

        /**
         * Sets a dynamic resolver for allowed issuer domains.
         * <p>
         * Cannot be used together with {@link #domains(List)}.
         * The resolver receives a {@link RequestContext} with the request URL,
         * headers, and unverified token issuer to make routing decisions.
         * </p>
         *
         * @param domainsResolver the resolver function
         * @return this builder
         */
        public Builder domainsResolver(DomainResolver domainsResolver) {
            this.domainsResolver = domainsResolver;
            return this;
        }

        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        public Builder dpopMode(DPoPMode mode) {
            this.dpopMode = mode;
            return this;
        }

        public Builder dpopIatOffsetSeconds(long iatOffset) {
            if (iatOffset < 0) {
                throw new IllegalArgumentException("dpopIatOffsetSeconds must not be negative");
            }
            this.dpopIatOffsetSeconds = iatOffset;
            return this;
        }

        public Builder dpopIatLeewaySeconds(long iatLeeway) {
            if (iatLeeway < 0) {
                throw new IllegalArgumentException("dpopIatLeewaySeconds must not be negative");
            }
            this.dpopIatLeewaySeconds = iatLeeway;
            return this;
        }

        /**
         * Sets the maximum number of entries for the default in-memory cache.
         * Both OIDC discovery and JWKS entries count against this limit.
         * Default: 100.
         * <p>
         * Ignored if a custom {@link AuthCache} is provided via
         * {@link #cache(AuthCache)}.
         * </p>
         *
         * @param maxEntries the maximum number of cache entries (must be positive)
         * @return this builder
         */
        public Builder cacheMaxEntries(int maxEntries) {
            if (maxEntries <= 0) {
                throw new IllegalArgumentException("cacheMaxEntries must be positive");
            }
            this.cacheMaxEntries = maxEntries;
            return this;
        }

        /**
         * Sets the TTL (time-to-live) in seconds for cached entries.
         * Default: 600 (10 minutes).
         * <p>
         * Ignored if a custom {@link AuthCache} is provided via
         * {@link #cache(AuthCache)}.
         * </p>
         *
         * @param ttlSeconds the TTL in seconds (must not be negative)
         * @return this builder
         */
        public Builder cacheTtlSeconds(long ttlSeconds) {
            if (ttlSeconds < 0) {
                throw new IllegalArgumentException("cacheTtlSeconds must not be negative");
            }
            this.cacheTtlSeconds = ttlSeconds;
            return this;
        }

        /**
         * Sets a custom cache implementation for both OIDC discovery metadata
         * and JWKS providers.
         * <p>
         * The cache uses a unified key-prefix scheme:
         * <ul>
         * <li>{@code discovery:{issuerUrl}} — for OIDC metadata</li>
         * <li>{@code jwks:{jwksUri}} — for JwkProvider instances</li>
         * </ul>
         * <p>
         * When set, {@link #cacheMaxEntries(int)} and {@link #cacheTtlSeconds(long)}
         * are ignored — the custom implementation controls its own eviction and TTL.
         * </p>
         *
         * @param cache the custom cache implementation
         * @return this builder
         */
        public Builder cache(AuthCache<Object> cache) {
            this.cache = cache;
            return this;
        }

        public AuthOptions build() {
            // Mutual exclusivity: domains and domainsResolver cannot both be set
            if (domains != null && !domains.isEmpty() && domainsResolver != null) {
                throw new IllegalArgumentException(
                        "Cannot configure both 'domains' and 'domainsResolver'. Use one or the other.");
            }

            // At least one domain source must be provided
            boolean hasDomain = domain != null && !domain.isEmpty();
            boolean hasDomains = domains != null && !domains.isEmpty();
            boolean hasResolver = domainsResolver != null;

            if (!hasDomain && !hasDomains && !hasResolver) {
                throw new IllegalArgumentException(
                        "At least one of 'domain', 'domains', or 'domainsResolver' must be configured.");
            }

            if (audience == null || audience.isEmpty()) {
                throw new IllegalArgumentException("Audience must not be null or empty");
            }
            return new AuthOptions(this);
        }
    }
}
