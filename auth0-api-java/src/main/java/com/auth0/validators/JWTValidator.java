package com.auth0.validators;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingRequiredArgumentException;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.models.AuthOptions;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.HttpRequestInfo;

import java.security.interfaces.RSAPublicKey;

import static com.auth0.jwt.JWT.require;

/**
 * JWT Validator for Auth0 tokens
 * 
 * This class provides functionality to validate JWT tokens using RSA256
 * algorithm
 * and JWKS (JSON Web Key Set) for public key retrieval.
 */
public class JWTValidator {

    private final AuthOptions authOptions;
    private final JwkProvider jwkProvider;

    /**
     * Creates a JWT validator with domain and audience.
     *
     * @param authOptions Authentication options containing domain and audience
     */
    public JWTValidator(AuthOptions authOptions) {
        if (authOptions == null) {
            throw new IllegalArgumentException("AuthOptions cannot be null");
        }

        this.authOptions = authOptions;
        this.jwkProvider = new UrlJwkProvider(authOptions.getDomain());
    }

    /**
     * Creates a JWT validator with domain and audience.
     *
     * @param authOptions Authentication options containing domain and audience
     */
    public JWTValidator(AuthOptions authOptions, JwkProvider jwkProvider) {
        if (authOptions == null) {
            throw new IllegalArgumentException("AuthOptions cannot be null");
        }
        if (jwkProvider == null) {
            throw new IllegalArgumentException("JwkProvider cannot be null");
        }
        this.authOptions = authOptions;
        this.jwkProvider = jwkProvider;
    }

    /**
     * Validates a JWT token
     * 
     * @param token the JWT token to validate
     * @return the decoded and verified JWT
     * @throws BaseAuthException if validation fails
     */
    public DecodedJWT validateToken(String token, HttpRequestInfo httpRequestInfo) throws BaseAuthException {

        if (token == null || token.trim().isEmpty()) {
            throw new MissingRequiredArgumentException("access_token");
        }

        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            Jwk jwk = jwkProvider.get(decodedJWT.getKeyId());
            RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = require(algorithm)
                    .withIssuer("https://" + authOptions.getDomain() + "/")
                    .withAudience(authOptions.getAudience())
                    .build();
            return verifier.verify(token);

        } catch (Exception e) {
            throw new VerifyAccessTokenException("signature verification failed", e);
        }
    }

    /**
     * Validates a JWT and ensures all required scopes are present.
     */
    public DecodedJWT validateTokenWithRequiredScopes(String token, HttpRequestInfo httpRequestInfo, String... requiredScopes)
            throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkRequiredScopes(jwt, requiredScopes);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures it has *any* of the provided scopes.
     */
    public DecodedJWT validateTokenWithAnyScope(String token, HttpRequestInfo httpRequestInfo, String... scopes)
            throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkAnyScope(jwt, scopes);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures a claim equals the expected value.
     */
    public DecodedJWT validateTokenWithClaimEquals(String token, HttpRequestInfo httpRequestInfo,  String claim, Object expected)
            throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimEquals(jwt, claim, expected);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures a claim includes all expected values.
     */
    public DecodedJWT validateTokenWithClaimIncludes(String token, HttpRequestInfo httpRequestInfo, String claim, Object... expectedValues)
            throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimIncludes(jwt, claim, expectedValues);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    public DecodedJWT validateTokenWithClaimIncludesAny(String token, HttpRequestInfo httpRequestInfo, String claim, Object... expectedValues)
            throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimIncludesAny(jwt, claim, expectedValues);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }


    public DecodedJWT decodeToken(String token) throws BaseAuthException {
        try {
            return JWT.decode(token);
        } catch (Exception e) {
            throw new VerifyAccessTokenException("Failed to decode JWT");
        }
    }

    private BaseAuthException wrapAsValidationException(Exception e) {
        if (e instanceof BaseAuthException) return (BaseAuthException) e;
        return new VerifyAccessTokenException("JWT claim validation failed");
    }

    public AuthOptions getAuthOptions() {
        return authOptions;
    }

    public JwkProvider getJwkProvider() {
        return jwkProvider;
    }
}
