package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingAuthorizationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
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

public class DisabledDPoPAuthenticationTest {
    private JWTValidator jwtValidator;
    private TokenExtractor extractor;
    private DisabledDPoPAuthentication auth;

    @Before
    public void setUp() {
        jwtValidator = mock(JWTValidator.class);
        extractor = mock(TokenExtractor.class);
        auth = new DisabledDPoPAuthentication(jwtValidator, extractor);
    }

    @Test
    public void authenticate_shouldAcceptBearerToken() throws Exception {
        DecodedJWT jwt = mock(DecodedJWT.class);

        when(extractor.extractBearer(anyMap())).thenReturn(
                new com.auth0.models.AuthToken("token", null, null));
        when(jwtValidator.validateToken(eq("token"), any(HttpRequestInfo.class))).thenReturn(jwt);
        when(jwt.getClaims()).thenReturn(new HashMap<>());

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        AuthenticationContext ctx = auth.authenticate(request);

        assertThat(ctx).isNotNull();
        verify(jwtValidator).validateToken(eq("token"), any(HttpRequestInfo.class));
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        when(extractor.extractBearer(anyMap()))
                .thenThrow(new MissingAuthorizationException());

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
    public void authenticate_shouldRejectMissingAuthorization() throws Exception {
        when(extractor.extractBearer(anyMap()))
                .thenThrow(new MissingAuthorizationException());

        Map<String, String> headers = new HashMap<>();
        HttpRequestInfo request = new HttpRequestInfo("GET", "https://api.example.com", headers);

        assertThatThrownBy(() -> auth.authenticate(request))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(ex -> {
                    BaseAuthException bae = (BaseAuthException) ex;
                    assertThat(bae.getHeaders()).containsKey("WWW-Authenticate");
                });
    }
}
