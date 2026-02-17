package com.auth0;

import com.auth0.exception.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.HttpRequestInfo;

import java.util.Map;

class AuthValidatorHelper {

    public static void validateBearerAuthorizationScheme(String scheme) throws BaseAuthException {
        if (!scheme.equalsIgnoreCase(AuthConstants.BEARER_SCHEME)) {
            throw new InvalidAuthSchemeException();
        }
    }

    public static void validateDpopAuthorizationScheme(String scheme) throws BaseAuthException {
        if (!scheme.equalsIgnoreCase(AuthConstants.DPOP_SCHEME)) {
            throw new InvalidAuthSchemeException();
        }
    }

    /**
     * Ensures NO 'cnf' claim exists in the JWT.
     * 
     * @param jwt the decoded JWT
     */
    public static void validateNotDpopBoundToken(DecodedJWT jwt) throws BaseAuthException {
        Map<String, Object> cnfClaim = jwt.getClaim("cnf").asMap();

        if (cnfClaim != null && !cnfClaim.isEmpty()) {
            throw new VerifyAccessTokenException(
                    "DPoP-bound token requires the DPoP authentication scheme, not Bearer.");
        }
    }

    /**
     * Ensures NO DPoP proof header exists.
     * Used in Bearer-only (DISABLED) mode.
     */
    public static void validateNoDpopProofPresence(Map<String, String> headers) throws BaseAuthException {
        if (headers.containsKey(AuthConstants.DPOP_HEADER)) {
            throw new InvalidAuthSchemeException("DPoP proof requires DPoP authentication scheme, not Bearer");
        }
    }

    /**
     * Ensures DPoP proof header exists.
     * 
     * @param proof the DPoP proof header value
     * @throws BaseAuthException exception if proof is missing or empty
     */
    public static void validateDpopProofPresence(String proof)
            throws BaseAuthException {

        if (proof == null || proof.trim().isEmpty()) {
            throw new InvalidAuthSchemeException();
        }
    }

    public static void validateNoMultipleProofsPresent(String proof) throws BaseAuthException {
        if (proof != null && proof.contains(",")) {
            throw new InvalidDpopProofException("Multiple DPoP proofs are not allowed");
        }
    }

    public static void validateHttpMethodAndHttpUrl(HttpRequestInfo requestInfo) throws BaseAuthException {
        if (requestInfo.getHttpMethod().isEmpty() || requestInfo.getHttpUrl().isEmpty()) {
            throw new MissingRequiredArgumentException("http_method/http_url");
        }
    }

    /**
     * Method to validate absence of DPoP token and proof for Allowed Mode.
     */
    public static void validateNoDpopPresence(Map<String, String> headers, DecodedJWT jwtToken) throws BaseAuthException{
        validateNotDpopBoundToken(jwtToken);
        validateNoDpopProofPresence(headers);
    }

}
