package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;

import java.util.Map;

/**
 * Orchestrates the authentication process using a specified strategy.
 */
class AuthenticationOrchestrator {
    private final AbstractAuthentication authStrategy;

    public AuthenticationOrchestrator(AbstractAuthentication authStrategy) {
        this.authStrategy = authStrategy;
    }

    public AuthenticationContext process(Map<String, String> headers, HttpRequestInfo requestInfo)
            throws BaseAuthException {
        return authStrategy.authenticate(headers, requestInfo);
    }
}
