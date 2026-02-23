package com.auth0.spring.boot;

import com.auth0.enums.DPoPMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Auth0 authentication and token validation.
 * <p>
 * This class binds Spring Boot configuration properties prefixed with
 * {@code auth0} to provide
 * configuration for JWT validation, DPoP support, and API access control.
 * <p>
 * Example configuration in {@code application.yml}:
 * 
 * <pre>
 * auth0:
 *   domain: "random-test.us.auth0.com"
 *   audience: "https://api.example.com/v2/"
 *   dpopMode: ALLOWED
 *   dpopIatOffsetSeconds: 300
 *   dpopIatLeewaySeconds: 60
 *   cacheMaxEntries: 200
 *   cacheTtlSeconds: 900
 * </pre>
 *
 * Multi-Custom Domain (MCD) Configuration
 * <p>
 * For tenants with multiple custom domains, use the {@code domains} list
 * instead of (or in addition to) the single {@code domain} property:
 * </p>
 * 
 *
 * auth0:
 *   audience: "https://api.example.com/v2/"
 *   domains:
 *     - "login.acme.com"
 *     - "auth.partner.com"
 *     - "random-test.us.auth0.com"
 *   cacheMaxEntries: 200
 *   cacheTtlSeconds: 900
 *
 *
 * When {@code domains} is configured, the SDK validates the token's {@code iss}
 * claim against all listed domains and performs OIDC discovery for the matching
 * issuer. The built-in in-memory cache handles caching of discovery metadata
 * and JWKS providers automatically.
 *
 *
 * 
 * @see com.auth0.enums.DPoPMode
 */
@ConfigurationProperties(prefix = "auth0")
public class Auth0Properties {
    private String domain;

    /**
     * Static list of allowed issuer domains for Multi-Custom Domain (MCD) support.
     * <p>
     * When configured, tokens whose {@code iss} claim matches any of these domains
     * will be accepted. Cannot be used together with a dynamic
     * {@code domainsResolver}.
     * Can coexist with {@link #domain} — if both are set, this list takes
     * precedence
     * for token validation.
     * </p>
     * Example:
     * 
     * <pre>
     * auth0:
     *   domains:
     *     - login.acme.com
     *     - auth.partner.com
     * </pre>
     */
    private java.util.List<String> domains;

    private String audience;
    private DPoPMode dpopMode;

    private Long dpopIatOffsetSeconds;
    private Long dpopIatLeewaySeconds;

    /**
     * Maximum number of entries in the unified in-memory cache
     * (OIDC discovery + JWKS providers). Default: 100.
     */
    private Integer cacheMaxEntries;

    /**
     * TTL in seconds for cached entries (OIDC discovery + JWKS providers).
     * Default: 600 (10 minutes).
     */
    private Long cacheTtlSeconds;

    /**
     * Gets the Auth0 domain configured for this application.
     * 
     * @return the Auth0 domain, or {@code null} if not configured
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Sets the Auth0 domain for this application.
     * 
     * @param domain the Auth0 domain to configure
     */
    public void setDomain(String domain) {
        this.domain = domain;
    }

    /**
     * Gets the list of allowed issuer domains for MCD support.
     *
     * @return the configured domains list, or {@code null} if not set
     */
    public java.util.List<String> getDomains() {
        return domains;
    }

    /**
     * Sets the list of allowed issuer domains for MCD support.
     *
     * @param domains list of allowed issuer domain strings
     */
    public void setDomains(java.util.List<String> domains) {
        this.domains = domains;
    }

    /**
     * Gets the audience (API identifier) for token validation.
     * 
     * @return the configured audience, or {@code null} if not set
     */
    public String getAudience() {
        return audience;
    }

    /**
     * Sets the audience (API identifier).
     * 
     * @param audience the audience to configure
     */
    public void setAudience(String audience) {
        this.audience = audience;
    }

    /**
     * Gets the DPoP mode for token validation.
     * 
     * @return the configured DPoP mode ({@code DISABLED}, {@code ALLOWED}, or
     *         {@code REQUIRED}), or {@code null} if not set
     */
    public DPoPMode getDpopMode() {
        return dpopMode;
    }

    /**
     * Sets the DPoP mode for token validation.
     * 
     * @param dpopMode the DPoP mode to configure ({@code DISABLED},
     *                 {@code ALLOWED}, or {@code REQUIRED})
     */
    public void setDpopMode(DPoPMode dpopMode) {
        this.dpopMode = dpopMode;
    }

    /**
     * Gets the DPoP proof iat (issued-at) offset in seconds.
     * 
     * @return the configured offset in seconds, or {@code null} if not set
     */
    public Long getDpopIatOffsetSeconds() {
        return dpopIatOffsetSeconds;
    }

    /**
     * Sets the DPoP proof iat (issued-at) offset in seconds.
     * 
     * @param dpopIatOffsetSeconds the offset in seconds to configure (must be
     *                             non-negative)
     * @throws IllegalArgumentException if the value is negative
     */
    public void setDpopIatOffsetSeconds(Long dpopIatOffsetSeconds) {
        if (dpopIatOffsetSeconds != null && dpopIatOffsetSeconds < 0) {
            throw new IllegalArgumentException("DPoP iat offset seconds must be non-negative");
        }
        this.dpopIatOffsetSeconds = dpopIatOffsetSeconds;
    }

    /**
     * Gets the DPoP proof iat (issued-at) leeway in seconds.
     * 
     * @return the configured leeway in seconds, or {@code null} if not set
     */
    public Long getDpopIatLeewaySeconds() {
        return dpopIatLeewaySeconds;
    }

    /**
     * Sets the DPoP proof iat (issued-at) leeway in seconds.
     * 
     * @param dpopIatLeewaySeconds the leeway in seconds to configure (must be
     *                             non-negative)
     * @throws IllegalArgumentException if the value is negative
     */
    public void setDpopIatLeewaySeconds(Long dpopIatLeewaySeconds) {
        if (dpopIatLeewaySeconds != null && dpopIatLeewaySeconds < 0) {
            throw new IllegalArgumentException("DPoP iat leeway seconds must be non-negative");
        }
        this.dpopIatLeewaySeconds = dpopIatLeewaySeconds;
    }

    /**
     * Gets the maximum number of entries for the in-memory cache.
     * 
     * @return the configured max entries, or {@code null} if not set (uses default
     *         of 100)
     */
    public Integer getCacheMaxEntries() {
        return cacheMaxEntries;
    }

    /**
     * Sets the maximum number of entries for the unified in-memory cache.
     * 
     * @param cacheMaxEntries the max entries to configure (must be positive)
     * @throws IllegalArgumentException if the value is not positive
     */
    public void setCacheMaxEntries(Integer cacheMaxEntries) {
        if (cacheMaxEntries != null && cacheMaxEntries <= 0) {
            throw new IllegalArgumentException("cacheMaxEntries must be positive");
        }
        this.cacheMaxEntries = cacheMaxEntries;
    }

    /**
     * Gets the TTL in seconds for cached entries.
     * 
     * @return the configured TTL in seconds, or {@code null} if not set (uses
     *         default of 600)
     */
    public Long getCacheTtlSeconds() {
        return cacheTtlSeconds;
    }

    /**
     * Sets the TTL in seconds for cached entries.
     * 
     * @param cacheTtlSeconds the TTL in seconds to configure (must not be negative)
     * @throws IllegalArgumentException if the value is negative
     */
    public void setCacheTtlSeconds(Long cacheTtlSeconds) {
        if (cacheTtlSeconds != null && cacheTtlSeconds < 0) {
            throw new IllegalArgumentException("cacheTtlSeconds must not be negative");
        }
        this.cacheTtlSeconds = cacheTtlSeconds;
    }
}
