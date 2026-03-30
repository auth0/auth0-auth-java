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
    public void getHeaderValue_returnsValidBase64Json() throws Exception {
        String headerValue = TelemetryProvider.getHeaderValue();
        assertThat(headerValue).isNotNull().isNotEmpty();

        byte[] decoded = Base64.getUrlDecoder().decode(headerValue);
        String json = new String(decoded, StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> payload = mapper.readValue(json, Map.class);

        assertThat(payload).containsKey("name");
        assertThat(payload).containsKey("version");
        assertThat(payload).containsKey("java");
        assertThat(payload.get("name")).isEqualTo("springboot-api");
        assertThat(payload.get("java")).isEqualTo(System.getProperty("java.version"));
    }

    @Test
    public void getHeaderValue_isCached() {
        String first = TelemetryProvider.getHeaderValue();
        String second = TelemetryProvider.getHeaderValue();
        assertThat(first).isSameAs(second);
    }
}
