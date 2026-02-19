package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidAuthSchemeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;

import java.util.Map;
class AllowedDPoPAuthentication extends AbstractAuthentication {

    public AllowedDPoPAuthentication(JWTValidator jwtValidator,
                                     DPoPProofValidator proofValidator,
                                     TokenExtractor extractor) {
        super(jwtValidator, extractor, proofValidator);
    }

    /**
     * Authenticates the request when DPoP Mode is Allowed (Accepts both DPoP and Bearer tokens) .
     * @param requestInfo HTTP request info
     * @return AuthenticationContext with JWT claims
     * @throws BaseAuthException if validation fails
     */
    @Override
    public AuthenticationContext authenticate(HttpRequestInfo requestInfo)
            throws BaseAuthException {

        String scheme = "";

        try{
            scheme = extractor.getScheme(requestInfo.getHeaders());

            if (scheme.equalsIgnoreCase(AuthConstants.BEARER_SCHEME)) {
                DecodedJWT jwtToken = validateBearerToken(requestInfo);
                AuthValidatorHelper.validateNoDpopPresence(requestInfo.getHeaders(), jwtToken);
                return buildContext(jwtToken);
            }

            if (scheme.equalsIgnoreCase(AuthConstants.DPOP_SCHEME)) {
                DecodedJWT decodedJWT = validateDpopTokenAndProof(requestInfo);
                return buildContext(decodedJWT);
            }

            throw new InvalidAuthSchemeException();
        } catch (BaseAuthException ex){
            throw prepareError(ex, DPoPMode.ALLOWED, scheme.isEmpty()? null : scheme);
        }

    }
}
