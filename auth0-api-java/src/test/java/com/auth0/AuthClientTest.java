package com.auth0;

import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidAuthSchemeException;
import com.auth0.exception.MissingAuthorizationException;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthClientTest {
    private static HttpRequestInfo REQUEST =
            new HttpRequestInfo("GET", "https://api.example.com/resource", null);

    @Test
    public void from_createsClient() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.ALLOWED));
        assertThat(client).isNotNull();

    }

    @Test
    public void allowedMode_isDefault() {
        AuthClient client = AuthClient.from(
                new AuthOptions.Builder()
                        .domain("test.auth0.com")
                        .audience("api")
                        .build()
        );

        assertThatThrownBy(() ->
                client.verifyRequest(Collections.emptyMap(), REQUEST)
        ).isInstanceOf(MissingAuthorizationException.class);
    }

    @Test
    public void allowedMode_rejectsUnknownScheme() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.ALLOWED));

        Map<String, String> headers = Collections.singletonMap("authorization", "Basic abc123");

        assertThatThrownBy(() ->
                client.verifyRequest(headers, REQUEST)
        ).isInstanceOf(InvalidAuthSchemeException.class);
    }

    @Test
    public void disabledMode_rejectsMissingAuthorization() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.DISABLED));

        assertThatThrownBy(() ->
                client.verifyRequest(Collections.emptyMap(), REQUEST)
        ).isInstanceOf(MissingAuthorizationException.class);
    }

    @Test
    public void disabledMode_rejectsDpopScheme() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.DISABLED));

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "DPoP token");
        headers.put("dpop", "proof");

        assertThatThrownBy(() ->
                client.verifyRequest(headers, REQUEST)
        ).isInstanceOf(BaseAuthException.class);
    }

    @Test
    public void requiredMode_rejectsBearerScheme() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.REQUIRED));

        Map<String, String> headers = Collections.singletonMap("authorization", "Bearer token");

        assertThatThrownBy(() ->
                client.verifyRequest(headers, REQUEST)
        ).isInstanceOf(BaseAuthException.class);
    }

    @Test
    public void requiredMode_rejectsMissingProof() {
        AuthClient client = AuthClient.from(validOptions(DPoPMode.REQUIRED));

        Map<String, String> headers = Collections.singletonMap("authorization", "DPoP token");


        assertThatThrownBy(() ->
                client.verifyRequest(headers, REQUEST)
        ).isInstanceOf(BaseAuthException.class);
    }

    private static AuthOptions validOptions(DPoPMode mode) {
        return new AuthOptions.Builder()
                .domain("test.auth0.com")
                .audience("https://api.example.com")
                .dpopMode(mode)
                .build();
    }
}
