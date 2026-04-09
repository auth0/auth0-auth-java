package com.auth0.models;

/**
 * Represents the relevant fields from the OIDC discovery document.
 */
public class OidcMetadata {

    private final String issuer;
    private final String jwksUri;

    public OidcMetadata(String issuer, String jwksUri) {
        this.issuer = issuer;
        this.jwksUri = jwksUri;
    }

    /**
     * Returns the {@code issuer} field from the discovery document.
     * This must exactly match the token's {@code iss} claim (Requirement 4).
     *
     * @return the issuer URL
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Returns the {@code jwks_uri} field from the discovery document.
     * This is the URL from which the JWKS (signing keys) should be fetched.
     *
     * @return the JWKS URI
     */
    public String getJwksUri() {
        return jwksUri;
    }
}
