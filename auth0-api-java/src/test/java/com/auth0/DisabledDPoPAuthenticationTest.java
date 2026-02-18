package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthenticationContext;
import com.auth0.validators.JWTValidator;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
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
                new com.auth0.models.AuthToken("token", null, null)
        );
        when(jwtValidator.validateToken("token", null)).thenReturn(jwt);
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");

        when(jwt.getClaims()).thenReturn(new HashMap<>());

        AuthenticationContext ctx = auth.authenticate(headers, null);


        assertThat(ctx).isNotNull();
        verify(jwtValidator).validateToken("token", null);
    }

    @Test
    public void authenticate_shouldWrapExceptionWithWwwAuthenticate() throws Exception {
        when(extractor.extractBearer(anyMap()))
                .thenThrow(new com.auth0.exception.MissingAuthorizationException());

        Map<String, String> headers = new HashMap<>();

        try {
            auth.authenticate(headers, null);
        } catch (BaseAuthException ex) {
            assertThat(ex.getHeaders())
                    .containsKey("WWW-Authenticate");
        }
    }
}
