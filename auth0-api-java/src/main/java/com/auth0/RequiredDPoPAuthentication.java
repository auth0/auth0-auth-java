package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;

class RequiredDPoPAuthentication extends AbstractAuthentication {

    public RequiredDPoPAuthentication(JWTValidator jwtValidator,
                                      DPoPProofValidator proofValidator,
                                      TokenExtractor extractor) {
        super(jwtValidator, extractor, proofValidator);
    }

    /**
     * Authenticates the request when DPoP Mode is Allowed (Accepts only DPoP tokens) .
     * @param requestInfo HTTP request info
     * @return AuthenticationContext with JWT claims
     * @throws BaseAuthException if validation fails
     */
    @Override
    public AuthenticationContext authenticate(HttpRequestInfo requestInfo)
            throws BaseAuthException {

//        Map<String, String> normalizedHeader = normalize(requestInfo.getHeaders());

        try {
            DecodedJWT decodedJWT = validateDpopTokenAndProof(requestInfo);
            return buildContext(decodedJWT);
        }
        catch (BaseAuthException ex){
            throw prepareError(ex, DPoPMode.REQUIRED, AuthConstants.DPOP_SCHEME);
        }
    }
}
