package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;

class DisabledDPoPAuthentication extends AbstractAuthentication {

    public DisabledDPoPAuthentication(JWTValidator jwtValidator, TokenExtractor extractor) {
        super(jwtValidator, extractor, null);
    }

    /**
     * Authenticates the request when DPoP Mode is Disabled (Accepts only Bearer tokens) .
     * @param requestInfo HTTP request info
     * @return AuthenticationContext with JWT claims
     * @throws BaseAuthException if validation fails
     */
    @Override
    public AuthenticationContext authenticate(HttpRequestInfo requestInfo)
            throws BaseAuthException {

//        Map<String, String> normalizedHeader = normalize(requestInfo.getHeaders());
        try {
            DecodedJWT jwt = validateBearerToken(requestInfo);

            return buildContext(jwt);
        } catch (BaseAuthException ex){
            throw prepareError(ex, DPoPMode.DISABLED, AuthConstants.BEARER_SCHEME);
        }
    }
}
