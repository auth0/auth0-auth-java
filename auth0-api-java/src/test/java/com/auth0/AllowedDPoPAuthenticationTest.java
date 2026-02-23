package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidAuthSchemeException;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class AllowedDPoPAuthenticationTest {
    private JWTValidator jwtValidator;
    private DPoPProofValidator dpopProofValidator;
    private TokenExtractor extractor;
    private AllowedDPoPAuthentication auth;

    @Before
    public void setUp() {
        jwtValidator = mock(JWTValidator.class);
        dpopProofValidator = mock(DPoPProofValidator.class);
        extractor = mock(TokenExtractor.class);
        auth = new AllowedDPoPAuthentication(jwtValidator, dpopProofValidator, extractor);
    }

    @Test
    public void authenticate_shouldAcceptBearerToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim cnfClaim = mock(Claim.class);
        when(cnfClaim.isNull()).thenReturn(true);
        when(cnfClaim.asMap()).thenReturn(null);
        when(jwt.getClaim("cnf")).thenReturn(cnfClaim);
        when(jwt.getClaims()).thenReturn(new HashMap<>());

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap())).thenReturn(
                new AuthToken("token", null, null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);

        AuthenticationContext ctx = auth.authenticate(request);

        assertThat(ctx).isNotNull();
        verify(jwtValidator).validateToken(eq("token"), any(HttpRequestInfo.class));
        verifyNoInteractions(dpopProofValidator);
    }

    @Test
    public void authenticate_shouldAcceptDpopToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getClaims()).thenReturn(new HashMap<>());

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        headers.put("dpop", "proof");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.DPOP_SCHEME);
        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenReturn(
                new AuthToken("token", "proof", null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);

        AuthenticationContext ctx = auth.authenticate(request);

        assertThat(ctx).isNotNull();
        verify(dpopProofValidator).validate("proof", jwt, request);
    }

    @Test
    public void authenticate_shouldRejectUnknownScheme() throws Exception {
        when(extractor.getScheme(anyMap())).thenReturn("basic");

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic abc");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        assertThatThrownBy(() -> auth.authenticate(request)).isInstanceOf(InvalidAuthSchemeException.class);
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap()))
                .thenThrow(new InvalidAuthSchemeException());

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer bad");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        try {
            auth.authenticate(request);
        } catch (BaseAuthException ex) {
            assertThat(ex.getHeaders())
                    .containsKey("WWW-Authenticate");
        }
    }

    @Test
    public void authenticate_shouldRejectBearerWithDpopProofPresent() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim cnfClaim = mock(Claim.class);
        when(cnfClaim.isNull()).thenReturn(true);
        when(cnfClaim.asMap()).thenReturn(null);
        when(jwt.getClaim("cnf")).thenReturn(cnfClaim);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");
        headers.put("dpop", "proof");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap())).thenReturn(
                new AuthToken("token", null, null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class);
    }

    @Test
    public void authenticate_shouldRejectBearerWithDpopBoundToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);
        Claim cnfClaim = mock(Claim.class);
        Map<String, Object> cnfMap = new HashMap<>();
        cnfMap.put("jkt", "thumbprint");
        when(cnfClaim.isNull()).thenReturn(false);
        when(cnfClaim.asMap()).thenReturn(cnfMap);
        when(jwt.getClaim("cnf")).thenReturn(cnfClaim);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap())).thenReturn(
                new AuthToken("token", null, null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class);
    }

    @Test
    public void authenticate_emptyScheme_shouldWrapWithWwwAuthenticate() throws Exception {
        when(extractor.getScheme(anyMap())).thenReturn("");

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(ex -> {
                    BaseAuthException bae = (BaseAuthException) ex;
                    assertThat(bae.getHeaders()).containsKey("WWW-Authenticate");
                });
    }
}
