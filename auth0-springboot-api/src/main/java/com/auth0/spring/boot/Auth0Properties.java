package com.auth0.spring.boot;

import com.auth0.enums.DPoPMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Auth0 authentication and token validation.
 * <p>
 * This class binds Spring Boot configuration properties prefixed with {@code auth0} to provide
 * configuration for JWT validation, DPoP support, and API access control.
 * <p>
 * Example configuration in {@code application.yml}:
 * <pre>
 * auth0:
 *   domain: "random-test.us.auth0.com"
 *   audience: "https://api.example.com/v2/"
 *   dpopMode: ALLOWED
 *   dpopIatOffsetSeconds: 300
 *   dpopIatLeewaySeconds: 60
 * </pre>
 * @see com.auth0.enums.DPoPMode
 */
@ConfigurationProperties(prefix = "auth0")
public class Auth0Properties {
    private String domain;
    private String audience;
    private DPoPMode dpopMode;

    private Long dpopIatOffsetSeconds;
    private Long dpopIatLeewaySeconds;

    /**
     * Gets the Auth0 domain configured for this application.
     * @return the Auth0 domain, or {@code null} if not configured
     */
    public String getDomain() { return domain; }

    /**
     * Sets the Auth0 domain for this application.
     * @param domain the Auth0 domain to configure
     */
    public void setDomain(String domain) { this.domain = domain; }

    /**
     * Gets the audience (API identifier) for token validation.
     * @return the configured audience, or {@code null} if not set
     */
    public String getAudience() { return audience; }

    /**
     * Sets the audience (API identifier).
     * @param audience the audience to configure
     */
    public void setAudience(String audience) { this.audience = audience; }

    /**
     * Gets the DPoP mode for token validation.
     * @return the configured DPoP mode ({@code DISABLED}, {@code ALLOWED}, or {@code REQUIRED}), or {@code null} if not set
     */
    public DPoPMode getDpopMode() {
        return dpopMode;
    }

    /**
     * Sets the DPoP mode for token validation.
     * @param dpopMode the DPoP mode to configure ({@code DISABLED}, {@code ALLOWED}, or {@code REQUIRED})
     */
    public void setDpopMode(DPoPMode dpopMode) {
        this.dpopMode = dpopMode;
    }

    /**
     * Gets the DPoP proof iat (issued-at) offset in seconds.
     * @return the configured offset in seconds, or {@code null} if not set
     */
    public Long getDpopIatOffsetSeconds() {
        return dpopIatOffsetSeconds;
    }

    /**
     * Sets the DPoP proof iat (issued-at) offset in seconds.
     * @param dpopIatOffsetSeconds the offset in seconds to configure (must be non-negative)
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
     * @return the configured leeway in seconds, or {@code null} if not set
     */
    public Long getDpopIatLeewaySeconds() {
        return dpopIatLeewaySeconds;
    }

    /**
     * Sets the DPoP proof iat (issued-at) leeway in seconds.
     * @param dpopIatLeewaySeconds the leeway in seconds to configure (must be non-negative)
     * @throws IllegalArgumentException if the value is negative
     */
    public void setDpopIatLeewaySeconds(Long dpopIatLeewaySeconds) {
        if (dpopIatLeewaySeconds != null && dpopIatLeewaySeconds < 0) {
            throw new IllegalArgumentException("DPoP iat leeway seconds must be non-negative");
        }
        this.dpopIatLeewaySeconds = dpopIatLeewaySeconds;
    }
}
