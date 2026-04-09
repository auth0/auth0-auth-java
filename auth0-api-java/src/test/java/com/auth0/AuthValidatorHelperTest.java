package com.auth0;

import com.auth0.exception.*;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.HttpRequestInfo;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;

public class AuthValidatorHelperTest {

    @Test
    public void validateBearerAuthorizationScheme_shouldAcceptBearer() throws BaseAuthException {
        AuthValidatorHelper.validateBearerAuthorizationScheme("Bearer");
        AuthValidatorHelper.validateBearerAuthorizationScheme("bearer");
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateBearerAuthorizationScheme_shouldRejectOtherSchemes() throws BaseAuthException {
        AuthValidatorHelper.validateBearerAuthorizationScheme("DPoP");
    }

    @Test
    public void validateDpopAuthorizationScheme_shouldAcceptDpop() throws BaseAuthException {
        AuthValidatorHelper.validateDpopAuthorizationScheme("DPoP");
        AuthValidatorHelper.validateDpopAuthorizationScheme("dpop");
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateDpopAuthorizationScheme_shouldRejectOtherSchemes() throws BaseAuthException {
        AuthValidatorHelper.validateDpopAuthorizationScheme("Bearer");
    }

    @Test
    public void validateNotDpopBoundToken_shouldPassWhenNoCnf() throws BaseAuthException {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);

        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(claim.asMap()).thenReturn(Collections.emptyMap());

        AuthValidatorHelper.validateNotDpopBoundToken(jwt);
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateNotDpopBoundToken_shouldThrowWhenCnfPresent() throws BaseAuthException {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);

        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(claim.asMap()).thenReturn(Collections.singletonMap("jkt", "value"));

        AuthValidatorHelper.validateNotDpopBoundToken(jwt);
    }

    @Test
    public void validateNoDpopProofPresence_shouldPassWhenMissing() throws BaseAuthException {
        Map<String, String> headers = new HashMap<>();
        AuthValidatorHelper.validateNoDpopProofPresence(headers);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateNoDpopProofPresence_shouldThrowWhenPresent() throws BaseAuthException {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.DPOP_HEADER, "proof");

        AuthValidatorHelper.validateNoDpopProofPresence(headers);
    }

    @Test
    public void validateDpopProofPresence_shouldPassWithValidProof() throws BaseAuthException {
        AuthValidatorHelper.validateDpopProofPresence("proof");
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateDpopProofPresence_shouldThrowWithNullProof() throws BaseAuthException {
        AuthValidatorHelper.validateDpopProofPresence(null);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateDpopProofPresence_shouldThrowWithEmptyProof() throws BaseAuthException {
        AuthValidatorHelper.validateDpopProofPresence("   ");
    }

    @Test
    public void validateNoMultipleProofsPresent_shouldPassSingleProof() throws BaseAuthException {
        AuthValidatorHelper.validateNoMultipleProofsPresent("proof");
    }

    @Test(expected = InvalidDpopProofException.class)
    public void validateNoMultipleProofsPresent_shouldThrowWithMultipleProofs() throws BaseAuthException {
        AuthValidatorHelper.validateNoMultipleProofsPresent("proof1,proof2");
    }

    @Test
    public void validateHttpMethodAndHttpUrl_shouldPassWithValidValues() throws BaseAuthException {
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://example.com", new HashMap<>());
        AuthValidatorHelper.validateHttpMethodAndHttpUrl(request);
    }

    @Test(expected = MissingRequiredArgumentException.class)
    public void validateHttpMethodAndHttpUrl_shouldThrowWithEmptyValues() throws BaseAuthException {
        HttpRequestInfo request = new HttpRequestInfo("", "", new HashMap<>());
        AuthValidatorHelper.validateHttpMethodAndHttpUrl(request);
    }

    @Test
    public void validateNoDpopPresence_shouldPassWithBearerToken() throws BaseAuthException {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(claim.asMap()).thenReturn(Collections.emptyMap());

        Map<String, String> headers = new HashMap<>();
        AuthValidatorHelper.validateNoDpopPresence(headers, jwt);
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateNoDpopPresence_shouldThrowWhenCnfPresent() throws BaseAuthException {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(claim.asMap()).thenReturn(Collections.singletonMap("jkt", "x"));

        Map<String, String> headers = new HashMap<>();
        AuthValidatorHelper.validateNoDpopPresence(headers, jwt);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void validateNoDpopPresence_shouldThrowWhenDpopHeaderPresent() throws BaseAuthException {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(claim.asMap()).thenReturn(Collections.emptyMap());

        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.DPOP_HEADER, "proof");

        AuthValidatorHelper.validateNoDpopPresence(headers, jwt);
    }
}
