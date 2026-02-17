package com.auth0;

import com.auth0.enums.AuthScheme;
import com.auth0.exception.*;
import com.auth0.models.AuthToken;

import java.util.Locale;
import java.util.Map;

class TokenExtractor {
    /**
     * Detects the auth scheme from headers.
     * Package-private: only strategies should call this.
     */
    String getScheme(Map<String, String> headers) throws BaseAuthException {
        return splitAuthHeader(headers.get(AuthConstants.AUTHORIZATION_HEADER))[0].toLowerCase(Locale.ROOT);
    }

    /** Extract Bearer token for DISABLED mode */
    public AuthToken extractBearer(Map<String, String> headers) throws BaseAuthException {
        String[] parts = splitAuthHeader(headers.get(AuthConstants.AUTHORIZATION_HEADER));
        String scheme = parts[0].toLowerCase(Locale.ROOT);
        String token = parts[1];

        AuthValidatorHelper.validateBearerAuthorizationScheme(scheme);
        return new AuthToken(token, null, AuthScheme.BEARER);
    }

    /** Extract DPoP token + proof for REQUIRED mode */
    public AuthToken extractDPoPProofAndDPoPToken(Map<String, String> headers) throws BaseAuthException {
        String[] parts = splitAuthHeader(headers.get(AuthConstants.AUTHORIZATION_HEADER));
        String scheme = parts[0].toLowerCase(Locale.ROOT);
        String token = parts[1];

        AuthValidatorHelper.validateDpopAuthorizationScheme(scheme);

        String proof = headers.get(AuthConstants.DPOP_HEADER);

        AuthValidatorHelper.validateNoMultipleProofsPresent(proof);
        AuthValidatorHelper.validateDpopProofPresence(proof);

        return new AuthToken(token, proof, AuthScheme.DPOP);
    }

    /**
     * Helper — split Authorization header safely.
     */
    private String[] splitAuthHeader(String authHeader) throws BaseAuthException {
        if (authHeader == null || authHeader.trim().isEmpty()) {
            throw new MissingAuthorizationException();
        }

        String[] parts = authHeader.trim().split("\\s+", 2);
        if (parts.length != 2 || parts[1].contains(" ")) {
            throw new MissingAuthorizationException();
        }
        return parts;
    }
}
