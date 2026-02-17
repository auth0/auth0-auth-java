package com.auth0.models;

import com.auth0.enums.AuthScheme;
import org.junit.Test;

import static org.junit.Assert.*;

public class AuthTokenTest {
    @Test
    public void testConstructorInitializesFieldsCorrectly() {
        AuthToken token = new AuthToken("access-token", "proof", AuthScheme.BEARER);

        assertEquals("access-token", token.getAccessToken());
        assertEquals("proof", token.getProof());
        assertEquals(AuthScheme.BEARER, token.getScheme());
    }

    @Test
    public void testGetAccessToken() {
        AuthToken token = new AuthToken("access-token", "proof", AuthScheme.BEARER);

        assertEquals("access-token", token.getAccessToken());
    }

    @Test
    public void testGetProof() {
        AuthToken token = new AuthToken("access-token", "proof", AuthScheme.BEARER);

        assertEquals("proof", token.getProof());
    }

    @Test
    public void testGetScheme() {
        AuthToken token = new AuthToken("access-token", "proof", AuthScheme.BEARER);

        assertEquals(AuthScheme.BEARER, token.getScheme());
    }

    @Test
    public void testHasProofReturnsTrueWhenProofIsNotNull() {
        AuthToken token = new AuthToken("access-token", "proof", AuthScheme.BEARER);

        assertTrue(token.hasProof());
    }

    @Test
    public void testHasProofReturnsFalseWhenProofIsNull() {
        AuthToken token = new AuthToken("access-token", null, AuthScheme.BEARER);

        assertFalse(token.hasProof());
    }
}
