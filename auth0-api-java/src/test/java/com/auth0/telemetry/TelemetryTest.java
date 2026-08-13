package com.auth0.telemetry;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class TelemetryTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decode(String value) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        return MAPPER.readValue(new String(decoded, StandardCharsets.UTF_8), Map.class);
    }

    @Test
    public void headerNameIsAuth0Client() {
        assertThat(Telemetry.HEADER_NAME).isEqualTo("Auth0-Client");
    }

    @Test
    public void coreIdentity_hasNoNestedCoreVersion() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-api-java", "1.2.3", null);
        Map<String, Object> payload = decode(telemetry.getValue());

        assertThat(payload.get("name")).isEqualTo("auth0-api-java");
        assertThat(payload.get("version")).isEqualTo("1.2.3");

        @SuppressWarnings("unchecked")
        Map<String, Object> env = (Map<String, Object>) payload.get("env");
        assertThat(env).doesNotContainKey("auth0-api-java");
        assertThat(env).containsKey("java");
    }

    @Test
    public void wrapperIdentity_reportsWrapperNameAndNestsCoreVersion() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-springboot-api", "2.0.0", "1.2.3");
        Map<String, Object> payload = decode(telemetry.getValue());

        assertThat(payload.get("name")).isEqualTo("auth0-springboot-api");
        assertThat(payload.get("version")).isEqualTo("2.0.0");

        @SuppressWarnings("unchecked")
        Map<String, Object> env = (Map<String, Object>) payload.get("env");
        assertThat(env.get("auth0-api-java")).isEqualTo("1.2.3");
        assertThat(env).containsKey("java");
    }

    @Test
    public void javaEnvUsesSpecificationVersion() throws Exception {
        Telemetry telemetry = new Telemetry("auth0-api-java", "1.0.0", null);
        Map<String, Object> payload = decode(telemetry.getValue());

        @SuppressWarnings("unchecked")
        Map<String, Object> env = (Map<String, Object>) payload.get("env");
        assertThat(env.get("java")).isEqualTo(System.getProperty("java.specification.version"));
    }

    @Test
    public void nullName_producesNullValue() {
        assertThat(new Telemetry(null, "1.0.0", null).getValue()).isNull();
    }

    @Test
    public void base64IsUrlSafeWithoutPadding() {
        String value = new Telemetry("auth0-springboot-api", "2.0.0", "1.2.3").getValue();
        assertThat(value).doesNotContain("=").doesNotContain("+").doesNotContain("/");
    }
}
