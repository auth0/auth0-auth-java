package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.models.AuthenticationContext;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;

import java.util.Map;

public class AuthClient {

    private final AuthenticationOrchestrator orchestrator;

    private AuthClient(AuthOptions options) {

        JWTValidator jwtValidator = new JWTValidator(options);
        DPoPProofValidator proofValidator = new DPoPProofValidator(options);
        TokenExtractor extractor = new TokenExtractor();

        AbstractAuthentication strategy;
        switch (options.getDpopMode()) {

            case REQUIRED:
                strategy = new RequiredDPoPAuthentication(jwtValidator, proofValidator, extractor);
                break;

            case DISABLED:
                strategy = new DisabledDPoPAuthentication(jwtValidator, extractor);
                break;

            case ALLOWED:
            default:
                strategy = new AllowedDPoPAuthentication(jwtValidator, proofValidator, extractor);
                break;
        }

        this.orchestrator = new AuthenticationOrchestrator(strategy);
    }

    public static AuthClient from(AuthOptions options) {
        return new AuthClient(options);
    }

    /**
     * Verifies the incoming request headers and HTTP request info.
     * @param headers request headers
     * @param requestInfo HTTP request info
     * @return AuthenticationContext with JWT claims
     * @throws BaseAuthException if verification fails
     */
    public AuthenticationContext verifyRequest(Map<String, String> headers, HttpRequestInfo requestInfo) throws BaseAuthException {
        return orchestrator.process(headers, requestInfo);
    }
}
