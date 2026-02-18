package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidRequestException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthToken;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

abstract class AbstractAuthentication {
    protected final JWTValidator jwtValidator;
    protected final TokenExtractor extractor;
    protected final DPoPProofValidator dpopProofValidator;

    protected AbstractAuthentication(JWTValidator jwtValidator, TokenExtractor extractor, DPoPProofValidator dpopProofValidator) {
        this.jwtValidator = jwtValidator;
        this.extractor = extractor;
        this.dpopProofValidator = dpopProofValidator;
    }
    /**
     * Concrete method to validate Bearer token headers and JWT claims.
     */
    protected DecodedJWT validateBearerToken(Map<String, String> headers, HttpRequestInfo httpRequestInfo) throws BaseAuthException {
        AuthToken authToken = extractor.extractBearer(headers);
        return jwtValidator.validateToken(authToken.getAccessToken(), httpRequestInfo);
    }

    /**
     * Concrete method to validate DPoP token headers, JWT claims, and proof.
     */
    protected DecodedJWT validateDpopTokenAndProof(Map<String, String> headers, HttpRequestInfo requestInfo)
            throws BaseAuthException {

        AuthValidatorHelper.validateHttpMethodAndHttpUrl(requestInfo);

        AuthToken authToken = extractor.extractDPoPProofAndDPoPToken(headers);
        DecodedJWT decodedJwtToken = jwtValidator.validateToken(authToken.getAccessToken(), requestInfo);

        dpopProofValidator.validate(authToken.getProof(), decodedJwtToken, requestInfo);

        return decodedJwtToken;
    }

    /**
     * Main abstract method for each concrete strategy.
     */
    public abstract AuthenticationContext authenticate(
            Map<String, String> headers,
            HttpRequestInfo requestInfo
    ) throws BaseAuthException;

    /**
     * Utility method to convert DecodedJWT claims to Map<String, Object>.
     */
    protected AuthenticationContext buildContext(DecodedJWT jwt) {
        Map<String, Object> claims = jwt.getClaims()
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().as(Object.class)
                ));

        return new AuthenticationContext(claims);
    }

    protected BaseAuthException prepareError(BaseAuthException ex, DPoPMode dpopMode, String scheme) {

        List<String> challenges = WWWAuthenticateBuilder.buildChallenges(ex.getErrorCode(), ex.getErrorDescription(), dpopMode, scheme);

        if (!challenges.isEmpty()) {
            String combinedChallenges = String.join(", ", challenges);
            ex.addHeader("WWW-Authenticate", combinedChallenges);
        }

        return ex;
    }

    Map<String, String> normalize(Map<String, String> headers) throws BaseAuthException {
        Map<String, String> normalized = new HashMap<>(headers.size());

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey().toLowerCase();
            if (normalized.containsKey(key)) {
                throw new InvalidRequestException("Duplicate HTTP header detected");
            }
            normalized.put(key, entry.getValue());
        }
        return normalized;
    }

}
