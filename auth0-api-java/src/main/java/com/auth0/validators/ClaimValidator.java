package com.auth0.validators;

import com.auth0.exception.*;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.*;

/**
 * Utility class for JWT claim validation
 *
 * Provides functionality to validate JWT claims including scopes and custom
 * claim checks.
 * This is the Java equivalent of the TypeScript claim validation utilities.
 */
class ClaimValidator {

    private ClaimValidator() {
    }

    /**
     * Returns a claim’s value as a normalized set of strings.
     * Handles both space-separated strings and string lists.
     */
    static Set<String> getClaimValues(DecodedJWT jwt, String claimName) throws BaseAuthException {

        if (!jwt.getClaims().containsKey(claimName)) {
            throw new VerifyAccessTokenException("Required claim is missing");
        }

        // Case 1: space-separated string
        String strValue = jwt.getClaim(claimName).asString();
        if (strValue != null) {
            return new HashSet<>(Arrays.asList(strValue.trim().split("\\s+")));
        }

        // Case 2: list of strings
        List<String> listValue = jwt.getClaim(claimName).asList(String.class);
        if (listValue != null) {
            return new HashSet<>(listValue);
        }

        throw new VerifyAccessTokenException("Unsupported format for claim");
    }

    static void validatePrimitive(Object expected) {
        if (expected != null &&
                !(expected instanceof String) &&
                !(expected instanceof Number) &&
                !(expected instanceof Boolean)) {
            throw new IllegalArgumentException("Expected value must be a string, number, boolean, or null");
        }
    }

    /**
     * Ensures the token includes *all* required scopes.
     */
    static void checkRequiredScopes(DecodedJWT jwt, String... requiredScopes)
            throws BaseAuthException {

        if (requiredScopes == null || requiredScopes.length == 0) {
            throw new IllegalArgumentException("At least one required scope must be specified");
        }

        Set<String> tokenScopes = getClaimValues(jwt, "scope");

        for (String scope : requiredScopes) {
            if (!tokenScopes.contains(scope)) {
                throw new InsufficientScopeException("Token is missing one or more required scopes");
            }
        }
    }

    /**
     * Ensures the token includes *at least one* of the given scopes.
     */
    static void checkAnyScope(DecodedJWT jwt, String... scopes)
            throws BaseAuthException {

        if (scopes == null || scopes.length == 0) {
            throw new IllegalArgumentException("At least one scope must be specified");
        }

        Set<String> tokenScopes = getClaimValues(jwt, "scope");

        for (String scope : scopes) {
            if (tokenScopes.contains(scope)) {
                return;
            }
        }

        throw new InsufficientScopeException("Token does not include any of the required scopes");
    }

    /**
     * Checks that a claim equals an expected value.
     */
    static void checkClaimEquals(DecodedJWT jwt, String claim, Object expected)
            throws BaseAuthException {

        if (claim == null || claim.trim().isEmpty()) {
            throw new IllegalArgumentException("Claim name must not be empty");
        }
        validatePrimitive(expected);

        Object claimValue = jwt.getClaim(claim).as(Object.class);

        if (!Objects.equals(claimValue, expected)) {
            throw new VerifyAccessTokenException("Claim validation failed");
        }
    }

    /**
     * Checks that a claim includes all expected values (for array or space-separated claims).
     */
    static void checkClaimIncludes(DecodedJWT jwt, String claim, Object... expectedValues)
            throws BaseAuthException {

        if (claim == null || claim.trim().isEmpty()) {
            throw new IllegalArgumentException("Claim name must not be empty");
        }

        for (Object v : expectedValues) validatePrimitive(v);

        Set<String> actualValues = getClaimValues(jwt, claim);
        for (Object v : expectedValues) {
            if (!actualValues.contains(v.toString())) {
                throw new VerifyAccessTokenException("Claim validation failed");
            }
        }
    }

    static void checkClaimIncludesAny(DecodedJWT jwt, String claim, Object... expectedValues)
            throws BaseAuthException {

        if (claim == null || claim.trim().isEmpty())
            throw new IllegalArgumentException("Claim name must not be empty");

        for (Object v : expectedValues) validatePrimitive(v);

        Set<String> actualValues = getClaimValues(jwt, claim);

        for (Object v : expectedValues) {
            if (actualValues.contains(v.toString())) {
                return;
            }
        }

        throw new VerifyAccessTokenException("Claim validation failed");
    }
}
