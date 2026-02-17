package com.auth0.models;

import java.util.Map;

public class AuthenticationContext {
    private final Map<String, Object> claims;

    public AuthenticationContext(Map<String, Object> claims) {
        this.claims = claims;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }
}
