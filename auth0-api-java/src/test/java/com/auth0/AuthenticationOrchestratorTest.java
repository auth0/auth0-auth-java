package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AuthenticationOrchestratorTest {

    @Test
    public void process_delegatesToStrategy() throws Exception {
        AbstractAuthentication strategy = mock(AbstractAuthentication.class);
        AuthenticationContext ctx = mock(AuthenticationContext.class);

        when(strategy.authenticate(any()))
                .thenReturn(ctx);

        AuthenticationOrchestrator orchestrator =
                new AuthenticationOrchestrator(strategy);

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer token");

        AuthenticationContext result =
                orchestrator.process(new HttpRequestInfo("GET", "https://api", headers));

        assertThat(result).isSameAs(ctx);
        verify(strategy).authenticate(any());
    }

    @Test
    public void process_propagatesException() throws Exception {
        AbstractAuthentication strategy = mock(AbstractAuthentication.class);
        BaseAuthException ex = mock(BaseAuthException.class);

        when(strategy.authenticate(any()))
                .thenThrow(ex);

        AuthenticationOrchestrator orchestrator =
                new AuthenticationOrchestrator(strategy);

        Map<String, String> headers = new HashMap<>();

        assertThatThrownBy(() ->
                orchestrator.process(new HttpRequestInfo("GET", "https://api", headers))
        ).isSameAs(ex);
    }
}
