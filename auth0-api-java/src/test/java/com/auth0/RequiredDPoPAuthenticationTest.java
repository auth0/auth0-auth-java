package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.auth0.validators.DPoPProofValidator;
import com.auth0.validators.JWTValidator;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
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
        HttpRequestInfo request =
                new HttpRequestInfo("POST", "https://api.example.com", null);

        when(extractor.extractDPoPProofAndDPoPToken(anyMap())).thenReturn(
                new com.auth0.models.AuthToken("token", "proof", null)
        );
        when(jwtValidator.validateToken("token")).thenReturn(jwt);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        headers.put("dpop", "proof");

        when(jwt.getClaims()).thenReturn(new HashMap<>());

        AuthenticationContext ctx = auth.authenticate(headers, request);

        assertThat(ctx).isNotNull();
        verify(dpopProofValidator).validate("proof", jwt, request);
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        HttpRequestInfo request =
                new HttpRequestInfo("POST", "https://api.example.com", null);
        when(extractor.extractDPoPProofAndDPoPToken(anyMap()))
                .thenThrow(new com.auth0.exception.MissingAuthorizationException());

        Map<String, String> headers = new HashMap<>();

        try {
            auth.authenticate(headers, request);
        } catch (BaseAuthException ex) {
            assertThat(ex.getHeaders())
                    .containsKey("WWW-Authenticate");
        }
    }
}
