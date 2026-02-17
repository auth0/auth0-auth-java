package com.auth0.models;

import com.auth0.enums.AuthScheme;

public class AuthToken {

    private final String accessToken;
    private final String proof;
    private final AuthScheme scheme;

    public AuthToken(String accessToken, String proof, AuthScheme scheme) {
        this.accessToken = accessToken;
        this.proof = proof;
        this.scheme = scheme;
    }

    public String getAccessToken() { return accessToken; }
    public String getProof() { return proof; }
    public AuthScheme getScheme() { return scheme; }

    public boolean hasProof() { return proof != null; }
}
