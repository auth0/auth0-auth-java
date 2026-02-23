package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingAuthorizationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthToken;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

public class RequiredDPoPAuthenticationTest {
    private JWTValidator jwtValidator;
    private DPoPProofValidator dpopProofValidator;
    private TokenExtractor extractor;
    private RequiredDPoPAuthentication auth;

    @Before
    public void setUp() {
        jwtValidator = mock(JWTValidator.class);
        dpopProofValidator = mock(DPoPProofValidator.class);
        extractor = mock(TokenExtractor.class);
        auth = new RequiredDPoPAuthentication(jwtValidator, dpopProofValidator, extractor);
    }

    @Test
    public void authenticate_shouldAcceptDpopToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        headers.put("dpop", "proof");
        HttpRequestInfo request = new HttpRequestInfo("POST", "https://api.example.com", headers);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenReturn(new AuthToken("token", "proof", null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);
        when(jwt.getClaims()).thenReturn(new HashMap<>());

        AuthenticationContext ctx = auth.authenticate(request);

        assertThat(ctx).isNotNull();
        verify(dpopProofValidator).validate("proof", jwt, request);
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        Map<String, String> headers = new HashMap<>();
        HttpRequestInfo request = new HttpRequestInfo("POST", "https://api.example.com", headers);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenThrow(new MissingAuthorizationException());

        try {
            auth.authenticate(request);
        } catch (BaseAuthException ex) {
            assertThat(ex.getHeaders())
                    .containsKey("WWW-Authenticate");
        }
    }

    @Test
    public void authenticate_shouldRejectMissingDpopProof() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        HttpRequestInfo request = new HttpRequestInfo("POST", "https://api.example.com", headers);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap()))
                .thenThrow(new com.auth0.exception.InvalidAuthSchemeException());

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(ex -> {
                    BaseAuthException bae = (BaseAuthException) ex;
                    assertThat(bae.getHeaders()).containsKey("WWW-Authenticate");
                });
    }

    @Test
    public void authenticate_shouldRejectMissingAuthorization() throws Exception {
        Map<String, String> headers = new HashMap<>();
        HttpRequestInfo request = new HttpRequestInfo("POST", "https://api.example.com", headers);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap()))
                .thenThrow(new MissingAuthorizationException());

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(ex -> {
                    BaseAuthException bae = (BaseAuthException) ex;
                    assertThat(bae.getHeaders()).containsKey("WWW-Authenticate");
                });
    }
}
