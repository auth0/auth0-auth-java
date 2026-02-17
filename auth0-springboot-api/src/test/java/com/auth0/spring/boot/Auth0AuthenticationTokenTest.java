package com.auth0.spring.boot;

import com.auth0.models.AuthenticationContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for Auth0AuthenticationToken
 */
class Auth0AuthenticationTokenTest {

    @Test
    @DisplayName("Should create SCOPE_ prefixed authorities from single scope in scope claim")
    void createAuthorities_shouldCreateScopePrefixedAuthorities_withSingleScope() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "read:users");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_read:users")));
    }

    @Test
    @DisplayName("Should create multiple SCOPE_ prefixed authorities from space-separated scopes")
    void createAuthorities_shouldCreateMultipleAuthorities_withSpaceSeparatedScopes() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "read:users write:users delete:users");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(3, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_read:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_write:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_delete:users")));
    }

    @Test
    @DisplayName("Should return ROLE_USER when scope claim is missing")
    void createAuthorities_shouldReturnRoleUser_whenScopeClaimMissing() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    @DisplayName("Should return ROLE_USER when scope claim is null")
    void createAuthorities_shouldReturnRoleUser_whenScopeClaimIsNull() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", null);
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    @DisplayName("Should return ROLE_USER when scope claim is not a String")
    void createAuthorities_shouldReturnRoleUser_whenScopeClaimIsNotString() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", Arrays.asList("read:users", "write:users"));
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    @DisplayName("Should return ROLE_USER when scope claim is empty string")
    void createAuthorities_shouldReturnRoleUser_whenScopeClaimIsEmptyString() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    @DisplayName("Should handle multiple consecutive spaces between scopes")
    void createAuthorities_shouldHandleMultipleSpaces_betweenScopes() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "read:users    write:users  delete:users");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(3, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_read:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_write:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_delete:users")));
    }

    @Test
    @DisplayName("Should set principal to sub claim value from authentication context")
    void constructor_shouldSetPrincipal_fromSubClaim() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "auth0|123456789");
        claims.put("scope", "read:users");
        when(context.getClaims()).thenReturn(claims);

        Auth0AuthenticationToken token = new Auth0AuthenticationToken(context);

        assertEquals("auth0|123456789", token.getPrincipal());
    }

    @Test
    @DisplayName("Should set authentication as authenticated on construction")
    void constructor_shouldSetAuthenticated_toTrue() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "auth0|123456789");
        claims.put("scope", "read:users");
        when(context.getClaims()).thenReturn(claims);

        Auth0AuthenticationToken token = new Auth0AuthenticationToken(context);

        assertTrue(token.isAuthenticated());
    }

    @Test
    @DisplayName("Should return null for credentials")
    void getCredentials_shouldReturnNull() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "auth0|123456789");
        when(context.getClaims()).thenReturn(claims);

        Auth0AuthenticationToken token = new Auth0AuthenticationToken(context);

        assertNull(token.getCredentials());
    }

    @Test
    @DisplayName("Should return authentication context from getter")
    void getAuthenticationContext_shouldReturnContext() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "auth0|123456789");
        when(context.getClaims()).thenReturn(claims);

        Auth0AuthenticationToken token = new Auth0AuthenticationToken(context);

        assertEquals(context, token.getAuthenticationContext());
    }

    @Test
    @DisplayName("Should create authorities with scopes containing special characters")
    void createAuthorities_shouldHandleSpecialCharacters_inScopes() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "read:users write:admin-panel delete:resource/123");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(3, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_read:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_write:admin-panel")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_delete:resource/123")));
    }

    @Test
    @DisplayName("Should handle scope claim with leading and trailing whitespace")
    void createAuthorities_shouldHandleWhitespace_aroundScopes() {
        AuthenticationContext context = mock(AuthenticationContext.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "  read:users write:users  ");
        when(context.getClaims()).thenReturn(claims);

        Collection<? extends GrantedAuthority> authorities = Auth0AuthenticationToken.createAuthorities(context);

        assertEquals(2, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_read:users")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("SCOPE_write:users")));
    }
}