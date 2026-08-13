package com.auth0.telemetry;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class TelemetryProviderTest {

    @Test
    @SuppressWarnings("unchecked")
    public void getDefault_returnsCoreIdentityAsValidBase64Json() throws Exception {
        String headerValue = TelemetryProvider.getDefault().getValue();
        assertThat(headerValue).isNotNull().isNotEmpty();

        byte[] decoded = Base64.getUrlDecoder().decode(headerValue);
        String json = new String(decoded, StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> payload = mapper.readValue(json, Map.class);

        assertThat(payload).containsKey("name");
        assertThat(payload).containsKey("version");
        assertThat(payload).containsKey("env");
        assertThat(payload.get("name")).isEqualTo("auth0-api-java");

        Map<String, Object> env = (Map<String, Object>) payload.get("env");
        assertThat(env.get("java")).isEqualTo(System.getProperty("java.specification.version"));
    }

    @Test
    public void getDefault_isCached() {
        Telemetry first = TelemetryProvider.getDefault();
        Telemetry second = TelemetryProvider.getDefault();
        assertThat(first).isSameAs(second);
    }

    @Test
    public void coreVersion_matchesDefaultTelemetryVersion() throws Exception {
        String headerValue = TelemetryProvider.getDefault().getValue();
        byte[] decoded = Base64.getUrlDecoder().decode(headerValue);
        Map<?, ?> payload = new ObjectMapper().readValue(
                new String(decoded, StandardCharsets.UTF_8), Map.class);

        assertThat(TelemetryProvider.coreVersion()).isEqualTo(payload.get("version"));
    }
}
