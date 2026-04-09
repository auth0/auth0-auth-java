package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InsufficientScopeException;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class ClaimValidatorTest {

    private DecodedJWT jwt;
    private Claim stringClaim;
    private Claim listClaim;

    @Before
    public void setUp() {
        jwt = mock(DecodedJWT.class);
        stringClaim = mock(Claim.class);
        listClaim = mock(Claim.class);
    }

    @Test
    public void testGetClaimValues_stringClaim() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("read write");

        Set<String> values = ClaimValidator.getClaimValues(jwt, "scope");
        assertEquals(new HashSet<>(Arrays.asList("read", "write")), values);
    }

    @Test
    public void testGetClaimValues_listClaim() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", listClaim));
        when(jwt.getClaim("scope")).thenReturn(listClaim);
        when(listClaim.asString()).thenReturn(null);
        when(listClaim.asList(String.class)).thenReturn(Arrays.asList("a", "b"));

        Set<String> values = ClaimValidator.getClaimValues(jwt, "scope");
        assertEquals(new HashSet<>(Arrays.asList("a", "b")), values);
    }

    @Test
    public void testGetClaimValues_missingClaim() {
        when(jwt.getClaims()).thenReturn(Collections.emptyMap());
        assertThatThrownBy(() -> ClaimValidator.getClaimValues(jwt, "missing"))
                .isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("Required claim is missing");
    }

    @Test
    public void testGetClaimValues_unsupportedFormat() {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn(null);
        when(stringClaim.asList(String.class)).thenReturn(null);

        assertThatThrownBy(() -> ClaimValidator.getClaimValues(jwt, "scope"))
                .isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("Unsupported format for claim");
    }

    @Test
    public void testValidatePrimitive_valid() {
        ClaimValidator.validatePrimitive("string");
        ClaimValidator.validatePrimitive(123);
        ClaimValidator.validatePrimitive(true);
        ClaimValidator.validatePrimitive(null);
    }

    @Test
    public void testValidatePrimitive_invalid() {
        assertThatThrownBy(() -> ClaimValidator.validatePrimitive(new Object()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Expected value must be a string");
    }

    @Test
    public void testCheckRequiredScopes_allPresent() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("read write");

        ClaimValidator.checkRequiredScopes(jwt, "read", "write");
    }

    @Test
    public void testCheckRequiredScopes_missingScope() {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("read");

        assertThatThrownBy(() -> ClaimValidator.checkRequiredScopes(jwt, "read", "write"))
                .isInstanceOf(InsufficientScopeException.class);
    }

    @Test
    public void testCheckAnyScope_present() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("read write");

        ClaimValidator.checkAnyScope(jwt, "write", "delete");
    }

    @Test
    public void testCheckAnyScope_nonePresent() {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("read");

        assertThatThrownBy(() -> ClaimValidator.checkAnyScope(jwt, "write"))
                .isInstanceOf(InsufficientScopeException.class);
    }

    @Test
    public void testCheckClaimEquals_matching() throws BaseAuthException {
        when(jwt.getClaim("name")).thenReturn(stringClaim);
        when(stringClaim.as(Object.class)).thenReturn("value");

        ClaimValidator.checkClaimEquals(jwt, "name", "value");
    }

    @Test
    public void testCheckClaimEquals_mismatch() {
        when(jwt.getClaim("name")).thenReturn(stringClaim);
        when(stringClaim.as(Object.class)).thenReturn("other");

        assertThatThrownBy(() -> ClaimValidator.checkClaimEquals(jwt, "name", "value"))
                .isInstanceOf(VerifyAccessTokenException.class);
    }

    @Test
    public void testCheckClaimEquals_invalidClaimName() {
        assertThatThrownBy(() -> ClaimValidator.checkClaimEquals(jwt, "", "value"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void testCheckClaimEquals_invalidExpected() {
        assertThatThrownBy(() -> ClaimValidator.checkClaimEquals(jwt, "claim", new Object()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void testCheckClaimIncludes_allPresent() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("a b c");

        ClaimValidator.checkClaimIncludes(jwt, "scope", "a", "b");
    }

    @Test
    public void testCheckClaimIncludes_missing() {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("a b");

        assertThatThrownBy(() -> ClaimValidator.checkClaimIncludes(jwt, "scope", "c"))
                .isInstanceOf(VerifyAccessTokenException.class);
    }

    @Test
    public void testCheckClaimIncludesAny_present() throws BaseAuthException {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("a b");

        ClaimValidator.checkClaimIncludesAny(jwt, "scope", "b", "c");
    }

    @Test
    public void testCheckClaimIncludesAny_nonePresent() {
        when(jwt.getClaims()).thenReturn(Collections.singletonMap("scope", stringClaim));
        when(jwt.getClaim("scope")).thenReturn(stringClaim);
        when(stringClaim.asString()).thenReturn("a b");

        assertThatThrownBy(() -> ClaimValidator.checkClaimIncludesAny(jwt, "scope", "c", "d"))
                .isInstanceOf(VerifyAccessTokenException.class);
    }
}
