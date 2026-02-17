package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidRequestException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthToken;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.*;

public class AbstractAuthenticationTest {
    private JWTValidator jwtValidator;
    private TokenExtractor extractor;
    private DPoPProofValidator dpopProofValidator;
    private TestAuthImpl authSystem;

    /**
     * Minimal concrete implementation for testing.
     */
    private static class TestAuthImpl extends AbstractAuthentication {
        TestAuthImpl(JWTValidator jwtValidator,
                     TokenExtractor extractor,
                     DPoPProofValidator dpopProofValidator) {
            super(jwtValidator, extractor, dpopProofValidator);
        }

        @Override
        public AuthenticationContext authenticate(
                Map<String, String> headers,
                HttpRequestInfo requestInfo) {
            return null;
        }
    }

    @Before
    public void setUp() {
        jwtValidator = mock(JWTValidator.class);
        extractor = mock(TokenExtractor.class);
        dpopProofValidator = mock(DPoPProofValidator.class);
        authSystem = new TestAuthImpl(jwtValidator, extractor, dpopProofValidator);
    }

    @Test
    public void normalize_shouldConvertKeysToLowercase() throws BaseAuthException {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token");
        headers.put("DPoP", "proof");

        Map<String, String> result = authSystem.normalize(headers);

        assertThat(result)
                .containsEntry("authorization", "Bearer token")
                .containsEntry("dpop", "proof");
    }

    @Test(expected = InvalidRequestException.class)
    public void normalize_shouldThrowOnDuplicateHeaders() throws BaseAuthException {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "a");
        headers.put("authorization", "b");

        authSystem.normalize(headers);
    }

    @Test
    public void validateBearerToken_shouldExtractAndValidate() throws Exception {
        AuthToken token = new AuthToken("access", null, null);
        DecodedJWT jwt = mock(DecodedJWT.class);

        when(extractor.extractBearer(anyMap())).thenReturn(token);
        when(jwtValidator.validateToken("access")).thenReturn(jwt);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer access");

        DecodedJWT result = authSystem.validateBearerToken(headers);

        assertThat(result).isSameAs(jwt);
    }

    @Test
    public void validateDpopTokenAndProof_shouldValidateEverything() throws Exception {
        AuthToken token = new AuthToken("access", "proof", null);
        DecodedJWT jwt = mock(DecodedJWT.class);
        HttpRequestInfo request =
                new HttpRequestInfo("GET", "https://api.example.com", null);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenReturn(token);
        when(jwtValidator.validateToken("access")).thenReturn(jwt);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP access");
        headers.put("dpop", "proof");

        DecodedJWT result = authSystem.validateDpopTokenAndProof(headers, request);

        verify(dpopProofValidator).validate("proof", jwt, request);
        assertThat(result).isSameAs(jwt);
    }

    @Test
    public void buildContext_shouldMapClaims() {
        Claim claim = mock(Claim.class);
        when(claim.as(Object.class)).thenReturn("user123");

        DecodedJWT jwt = mock(DecodedJWT.class);

        Map<String, Claim> claimsMap = new HashMap<>();
        claimsMap.put("sub", claim);

        when(jwt.getClaims()).thenReturn(claimsMap);

        AuthenticationContext ctx = authSystem.buildContext(jwt);

        assertThat(ctx.getClaims())
                .containsEntry("sub", "user123");
    }

    @Test
    public void prepareError_shouldAddWwwAuthenticateHeader() {
        BaseAuthException ex = mock(BaseAuthException.class);
        when(ex.getErrorCode()).thenReturn("invalid_token");
        when(ex.getErrorDescription()).thenReturn("desc");

        BaseAuthException result =
                authSystem.prepareError(ex, DPoPMode.ALLOWED, "bearer");

        verify(ex).addHeader(eq("WWW-Authenticate"), anyString());
        assertThat(result).isSameAs(ex);
    }
}
