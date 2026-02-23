package com.auth0.models;

/**
 * Represents the relevant fields from an OIDC Discovery document
 * ({@code .well-known/openid-configuration}).
 * <p>
 * Only the fields required for JWT validation are extracted:
 * <ul>
 * <li>{@code issuer} — the canonical issuer identifier (used for
 * double-validation)</li>
 * <li>{@code jwks_uri} — the URL of the JSON Web Key Set (used to fetch signing
 * keys)</li>
 * </ul>
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
