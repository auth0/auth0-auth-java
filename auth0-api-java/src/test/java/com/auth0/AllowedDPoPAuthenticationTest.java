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
import static org.mockito.ArgumentMatchers.*;
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

        Claim claim = mock(Claim.class);

        when(claim.isNull()).thenReturn(true);
        when(jwt.getClaim("cnf")).thenReturn(claim);
        when(jwt.getClaims()).thenReturn(new HashMap<>());

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap())).thenReturn(
                new AuthToken("token", null, null)
        );

        when(jwtValidator.validateToken(eq("token"), any())).thenReturn(jwt);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");

        HttpRequestInfo httpRequestInfo = new HttpRequestInfo("GET", "https://api.example.com", headers);

        AuthenticationContext ctx = auth.authenticate(httpRequestInfo);

        assertThat(ctx).isNotNull();
        verify(jwtValidator).validateToken("token", httpRequestInfo);
        verifyNoInteractions(dpopProofValidator);
    }

    @Test
    public void authenticate_shouldAcceptDpopToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);

        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.DPOP_SCHEME);
        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenReturn(
                new com.auth0.models.AuthToken("token", "proof", null)
        );
        when(jwtValidator.validateToken(eq("token"), any())).thenReturn(jwt);
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        headers.put("dpop", "proof");

        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        when(jwt.getClaims()).thenReturn(new HashMap<>());

        AuthenticationContext ctx = auth.authenticate(request);

        assertThat(ctx).isNotNull();
        verify(dpopProofValidator).validate("proof", jwt, request);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void authenticate_shouldRejectUnknownScheme() throws Exception {
        when(extractor.getScheme(anyMap())).thenReturn("basic");

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic abc");

        HttpRequestInfo request = new HttpRequestInfo(headers);

        auth.authenticate(request);
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        when(extractor.getScheme(anyMap())).thenReturn(AuthConstants.BEARER_SCHEME);
        when(extractor.extractBearer(anyMap()))
                .thenThrow(new InvalidAuthSchemeException());

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer bad");

        HttpRequestInfo request = new HttpRequestInfo(headers);

        try {
            auth.authenticate(request);
        } catch (BaseAuthException ex) {
            assertThat(ex.getHeaders())
                    .containsKey("WWW-Authenticate");
        }
    }
}
